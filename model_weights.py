"""Local numerical weight evidence, separate from serialization and behavior tests."""
import re
import containers
import engine
import model_tools


def assess(config, progress, stop):
    path = model_tools.target(config.get('path', ''))
    expected = str(config.get('sha256', '')).strip().lower()
    if expected and (not path.is_file() or not re.fullmatch('[a-f0-9]{64}', expected)):
        raise ValueError('Expected SHA-256 requires one file and a 64-character trusted digest.')
    progress('Reading Safetensors headers and streaming numerical weights locally…')
    data = model_tools.worker('weight_worker.py', {'path': str(path)}, stop)
    findings = []
    def add(name, status, evidence, recommendation):
        findings.append(engine.finding(name, status, evidence, recommendation, 'Numerical weights'))
    nonfinite = zero = 0
    for file in data['files']:
        for tensor in file['tensors']:
            nonfinite += tensor.get('nan', 0) + tensor.get('infinity', 0)
            zero += bool(tensor.get('elements') and tensor.get('zeros') == tensor.get('elements'))
    add('Non-finite weight values', 'attention' if nonfinite else 'pass' if data['complete'] else 'unknown',
        f'{nonfinite} NaN/Infinity values observed in analyzed tensors.',
        'Investigate non-finite values with the model owner. No detections on incomplete data is inconclusive.')
    if zero:
        add('All-zero tensors require context', 'review', f'{zero} nonempty tensors contain only zero values.',
            'Compare with the intended architecture and trusted original. Zero initialization can be legitimate; this is not a backdoor verdict.')
    if not data['complete']:
        add('Weight-analysis coverage incomplete', 'unknown', 'Some files, tensor dtypes, or byte ranges were not fully analyzed. See per-file gaps.',
            'Review the coverage details; narrow the target or use a supported format. Other formats remain available in the supply-chain scanner.')
    observed = data['files'][0].get('sha256') if path.is_file() and len(data['files']) == 1 else None
    if expected:
        add('Trusted artifact digest comparison', 'unknown' if not observed else 'pass' if observed == expected else 'attention',
            'Hash unavailable for incomplete or changing file.' if not observed else 'Observed SHA-256: ' + observed + ('. Matches supplied digest.' if observed == expected else '. DOES NOT MATCH supplied digest.'),
            'A matching independently trusted digest establishes file identity only. The app does not authenticate the expected digest.')
    return {'schema': 'sha-report-v1', 'type': 'Model weight analysis', 'version': engine.VERSION,
            'createdAt': containers.now(), 'target': str(path),
            'status': 'cancelled' if stop.is_set() else 'complete' if data['complete'] else 'partial',
            'findings': findings, 'weightAnalysis': data, 'coverage': data['coverage'],
            'limitations': ['Full streaming numerical analysis of selected Safetensors files only; no sampling, inference, model loading or pickle execution.',
            'Supported numerical dtypes: F64, F32, F16, BF16, signed/unsigned 8/16/32/64-bit integers and BOOL. Other dtypes remain unsupported. Integer statistics use float64 and can lose integer precision.',
            'Folder scope includes discovered Safetensors files only. Missing shards, model architecture completeness and training provenance are not established.',
            'Limits: 180 seconds, 16 GiB total bytes, 128 files, 4 MiB headers, 4,096 tensors, 10,000 directory entries. Partial and changing files remain inconclusive.',
            'NaN/Infinity, zeros and statistical patterns are evidence for review; they do not prove or exclude learned backdoors, poisoning, malware or unsafe behavior.',
            'Statistics use finite values only; NaN/Infinity and zero counts are separate. Metadata values and raw weights are not exported. Tensor names and paths may be sensitive.',
            'Run ModelAudit separately for serialization/opcode security and behavior evaluation against an authorized inference endpoint. This is not a safety certification.']}
