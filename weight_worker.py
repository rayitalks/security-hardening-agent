"""Bounded, read-only Safetensors analysis. Never imports a model or unpickles data."""
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import sys
import time

VERSION = '1.0.0'
MAX_BYTES = 16 * 1024**3
MAX_HEADER = 4 * 1024**2
MAX_TENSORS = 4096
MAX_FILES = 128
DTYPES = {'F64': ('<f8', 8), 'F32': ('<f4', 4), 'F16': ('<f2', 2),
          'BF16': ('<u2', 2), 'I64': ('<i8', 8), 'U64': ('<u8', 8),
          'I32': ('<i4', 4), 'U32': ('<u4', 4), 'I16': ('<i2', 2),
          'U16': ('<u2', 2), 'I8': ('i1', 1), 'U8': ('u1', 1), 'BOOL': ('?', 1)}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON keys in header.')
        result[key] = value
    return result


def linked(path):
    # Windows junctions must not widen a selected directory's scope.
    return path.is_symlink() or (os.name == 'nt' and bool(path.lstat().st_file_attributes & 0x400))


def inventory(root):
    if linked(root):
        raise ValueError('Linked files and folders are not supported.')
    if root.is_file():
        return [root], []
    files, gaps, seen = [], [], 0
    def failed(_):
        gaps.append('A directory could not be inventoried.')
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=failed):
        seen += len(dirs) + len(names)
        if seen > 10000:
            gaps.append('Inventory exceeded 10,000 entries.'); break
        kept = []
        for name in sorted(dirs):
            if linked(Path(directory) / name):
                gaps.append('A linked directory was omitted.')
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix.lower() != '.safetensors':
                continue
            if linked(path):
                gaps.append('A linked Safetensors file was omitted.'); continue
            if len(files) >= MAX_FILES:
                return files, gaps + ['Inventory exceeded 128 Safetensors files.']
            files.append(path)
    return files, gaps


def header(stream, size):
    prefix = stream.read(8)
    if len(prefix) != 8:
        raise ValueError('Missing Safetensors header length.')
    length = struct.unpack('<Q', prefix)[0]
    if not 2 <= length <= min(MAX_HEADER, size - 8):
        raise ValueError('Invalid or oversized Safetensors header (4 MiB limit).')
    raw = stream.read(length)
    if not raw.startswith(b'{'):
        raise ValueError('Safetensors header must start with a JSON object.')
    data = json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-JSON number in header.')))
    if not isinstance(data, dict) or len(data) > MAX_TENSORS + 1:
        raise ValueError('Invalid header or more than 4,096 tensor entries.')
    metadata = data.pop('__metadata__', {})
    if not isinstance(metadata, dict) or any(not isinstance(v, str) for v in metadata.values()):
        raise ValueError('Invalid Safetensors metadata.')
    tensors = []
    for name, value in data.items():
        if not name or len(name) > 512 or not isinstance(value, dict):
            raise ValueError('Invalid or oversized tensor name/descriptor.')
        shape, offsets, dtype = value.get('shape'), value.get('data_offsets'), value.get('dtype')
        if not isinstance(shape, list) or len(shape) > 32 or any(type(n) is not int or not 0 <= n <= 2**63-1 for n in shape):
            raise ValueError('Invalid tensor shape.')
        count = math.prod(shape)
        if count > 2**63-1:
            raise ValueError('Tensor element count exceeds supported range.')
        if not isinstance(dtype, str) or len(dtype) > 32:
            raise ValueError('Invalid tensor dtype.')
        if not isinstance(offsets, list) or len(offsets) != 2 or any(type(n) is not int for n in offsets):
            raise ValueError('Invalid tensor data offsets.')
        start, end = offsets
        if not 0 <= start <= end <= size - 8 - length:
            raise ValueError('Tensor extends outside the data buffer.')
        if dtype in DTYPES and end - start != count * DTYPES[dtype][1]:
            raise ValueError('Tensor shape/dtype does not match its byte length.')
        tensors.append(dict(name=name, dtype=dtype, shape=shape, elements=count, start=start, end=end))
    tensors.sort(key=lambda row: (row['start'], row['end']))
    cursor = 0
    for row in tensors:
        if row['start'] != cursor:
            raise ValueError('Tensor ranges overlap or leave gaps in the data buffer.')
        cursor = row['end']
    if cursor != size - 8 - length:
        raise ValueError('Unindexed trailing bytes in Safetensors file.')
    return prefix + raw, tensors


def analyze_file(path, remaining_bytes, remaining_tensors, deadline):
    import numpy as np
    result = {'file': str(path), 'status': 'partial', 'sha256': None, 'tensors': [], 'gaps': []}
    before = path.stat()
    result['bytes'] = before.st_size
    if linked(path) or not path.is_file():
        result['gaps'].append('File became a link or is not a regular file.'); return result
    if before.st_size > remaining_bytes:
        result['gaps'].append('File exceeds the remaining 16 GiB byte budget.'); return result
    try:
        with path.open('rb') as stream:
            opened_before = os.fstat(stream.fileno())
            raw_header, tensors = header(stream, before.st_size)
            result['tensorCount'] = len(tensors)
            if len(tensors) > remaining_tensors:
                result['gaps'].append('File exceeds the remaining 4,096 tensor budget.'); return result
            file_hash = hashlib.sha256(raw_header)
            result['bytesRead'] = len(raw_header)
            for tensor in tensors:
                row = {k: v for k, v in tensor.items() if k not in ('start', 'end')}
                row.update(status='partial', sha256=None)
                result['tensors'].append(row)
                digest = hashlib.sha256()
                finite_count = nan = inf = zeros = 0
                scale = total = square_total = 0.0
                minimum = maximum = None
                remaining = tensor['end'] - tensor['start']
                supported = tensor['dtype'] in DTYPES
                while remaining:
                    if time.monotonic() >= deadline:
                        result['gaps'].append('180-second analysis budget reached.'); return result
                    raw = stream.read(min(1024 * 1024, remaining))
                    if not raw:
                        raise ValueError('File was truncated during analysis.')
                    remaining -= len(raw)
                    result['bytesRead'] += len(raw)
                    digest.update(raw); file_hash.update(raw)
                    if not supported:
                        continue
                    values = np.frombuffer(raw, dtype=DTYPES[tensor['dtype']][0])
                    if tensor['dtype'] == 'BF16':
                        values = (values.astype(np.uint32) << 16).view(np.float32)
                    values = values.astype(np.float64)
                    nan += int(np.isnan(values).sum()); inf += int(np.isinf(values).sum())
                    values = values[np.isfinite(values)]
                    zeros += int((values == 0).sum())
                    finite_count += int(values.size)
                    if values.size:
                        lo, hi = float(values.min()), float(values.max())
                        minimum = lo if minimum is None else min(minimum, lo)
                        maximum = hi if maximum is None else max(maximum, hi)
                        new_scale = max(scale, abs(lo), abs(hi))
                        if new_scale:
                            ratio = scale / new_scale
                            total *= ratio; square_total *= ratio * ratio; scale = new_scale
                            normalized = values / scale
                            total += float(normalized.sum()); square_total += float(np.square(normalized).sum())
                row['sha256'] = digest.hexdigest()
                if supported:
                    mean = total / finite_count if finite_count else 0
                    variance = max(0.0, square_total / finite_count - mean * mean) if finite_count else 0
                    row.update(status='complete', finite=finite_count, nan=nan, infinity=inf, zeros=zeros,
                               minimum=minimum, maximum=maximum,
                               mean=min(1.0, max(-1.0, mean)) * scale if finite_count else None,
                               stddev=min(1.0, math.sqrt(variance)) * scale if finite_count else None)
                else:
                    row['status'] = 'unsupported'
                    result['gaps'].append('Numerical analysis unavailable for dtype ' + tensor['dtype'] + '.')
            after = path.stat()
            opened = os.fstat(stream.fileno())
            # On Windows Path.stat and fstat can expose different ctime semantics.
            # Compare change time only within each API, and common identity across APIs.
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
            if (identity(before) != identity(after) or identity(before) != identity(opened)
                    or before.st_ctime_ns != after.st_ctime_ns
                    or identity(opened_before) != identity(opened) or opened_before.st_ctime_ns != opened.st_ctime_ns):
                result['gaps'].append('File changed while being analyzed; hashes are not stable identity evidence.')
            else:
                result['sha256'] = file_hash.hexdigest()
            result['status'] = 'complete' if not result['gaps'] else 'partial'
    except (ValueError, OSError, OverflowError, RecursionError, MemoryError):
        result['gaps'].append('Malformed, unreadable or unsupported Safetensors file; structural validation failed.')
    return result


def scan(path, max_bytes=MAX_BYTES, seconds=180):
    root = Path(path)
    deadline = time.monotonic() + seconds
    files, gaps = inventory(root)
    results, consumed, tensor_count = [], 0, 0
    for file in files:
        if time.monotonic() >= deadline:
            gaps.append('Analysis time budget reached before all files were read.'); break
        row = analyze_file(file, max_bytes - consumed, MAX_TENSORS - tensor_count, deadline)
        consumed += row.get('bytesRead', 0); tensor_count += len(row['tensors']); results.append(row)
    if not files:
        gaps.append('No Safetensors files found. Use ModelAudit for other model formats.')
    if not tensor_count:
        gaps.append('No tensors were numerically analyzed.')
    elif not any(t.get('elements') for f in results for t in f['tensors']):
        gaps.append('No weight values found; empty tensors alone do not establish numerical coverage.')
    complete = bool(tensor_count) and len(results) == len(files) and not gaps and all(r['status'] == 'complete' for r in results)
    return {'engine': 'Ray-i Safetensors numerical analyzer', 'version': VERSION, 'complete': complete,
            'files': results, 'gaps': gaps, 'coverage': {'filesSelected': len(files), 'filesAttempted': len(results),
            'filesComplete': sum(r['status'] == 'complete' for r in results), 'bytesRead': consumed,
            'tensorsInspected': tensor_count, 'sampling': False, 'maxBytes': max_bytes, 'budgetSeconds': seconds}}


if __name__ == '__main__':
    from skillspector_worker import install_network_guard
    install_network_guard()
    request = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    result = scan(request['path'])
    Path(request['output']).write_text(json.dumps(result, allow_nan=False), encoding='utf-8')
