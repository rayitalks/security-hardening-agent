"""Read-only dependency CVE checks, KEV enrichment, and exposure indicators.

Only package identity/version is sent to OSV. No code is imported or executed.
Offline snapshots are exact-query evidence, not a general vulnerability database.
"""
import concurrent.futures
import datetime as dt
import json
import os
from pathlib import Path
import re
import threading
import time
import urllib.parse
import urllib.request

import engine

try:
    import tomllib
except ImportError:
    tomllib = None

OSV_URL = 'https://api.osv.dev/v1/query'
KEV_URLS = (
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
)
ECOSYSTEMS = ('PyPI', 'npm', 'Go', 'Maven', 'crates.io', 'RubyGems', 'NuGet', 'Packagist')
PURL_ECOSYSTEMS = dict(pypi='PyPI', npm='npm', golang='Go', maven='Maven', cargo='crates.io', gem='RubyGems', nuget='NuGet', composer='Packagist')
IGNORED = {'.git', '.venv', '.runtime', 'venv', 'node_modules', 'vendor', 'dist', 'build', '__pycache__'}
MAX_PACKAGES = 200
MAX_ADVISORIES = 50
MAX_FINDINGS = 1500
MAX_ENTRIES = 5000
STALE_DAYS = 7
CVE = re.compile(r'CVE-\d{4}-\d{4,}', re.I)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def old(value):
    try:
        stamp = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            return True
        age = dt.datetime.now(dt.timezone.utc) - stamp
        return age.total_seconds() < -86400 or age.days > STALE_DAYS
    except (ValueError, TypeError):
        return True


def clean(value, limit=500):
    return str(value or '')[:limit]


def package(ecosystem, name, version, source='Manual entry'):
    if ecosystem not in ECOSYSTEMS or not isinstance(name, str) or not isinstance(version, str):
        return None
    # Reject paths, credentials, ranges and URL/direct references rather than guess versions.
    if not re.fullmatch(r'[@A-Za-z0-9][@A-Za-z0-9._/+:-]{0,239}', name) or '://' in name or '..' in name.split('/'):
        return None
    if not re.fullmatch(r'v?\d[A-Za-z0-9.!+_\-]{0,119}', version):
        return None
    if ecosystem == 'PyPI':
        name = re.sub(r'[-_.]+', '-', name).lower()
    return {'ecosystem': ecosystem, 'name': name, 'version': version, 'source': source}


def key(pkg):
    return (pkg['ecosystem'], pkg['name'], pkg['version'])


def read_json(path, limit=16*1024*1024):
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('File exceeds the read limit.')
    return json.loads(data.decode('utf-8-sig'))


def walk(root, notes, stop):
    count = 0
    for current, dirs, files in os.walk(root, followlinks=False, onerror=lambda _: notes.append('A directory could not be read.')):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED and not (Path(current)/d).is_symlink() and (Path(current)/d).resolve().is_relative_to(root))
        count += len(dirs)
        for name in sorted(files):
            count += 1
            if stop.is_set() or count > MAX_ENTRIES:
                notes.append('Traversal cancelled or the 5,000-entry limit was reached.')
                return
            path = Path(current)/name
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                notes.append('A symlink or path outside the selected folder was skipped.')
                continue
            yield path


def inventory(target, stop=None):
    stop = stop or threading.Event()
    root = Path(target).expanduser()
    if not root.is_absolute() or not root.exists():
        raise ValueError('Choose an existing absolute folder, manifest, or CycloneDX JSON file path.')
    root = root.resolve()
    notes, found, manifests = [], {}, []

    def add(eco, name, version, source):
        row = package(eco, name, version, source)
        if row:
            if key(row) not in found:
                if len(found) >= MAX_PACKAGES:
                    raise ValueError('The 200 unique package/version limit was reached.')
                found[key(row)] = row
        else:
            notes.append(source + ': a dependency had an unresolved version or unsupported identity; it was not queried.')

    def npm_v1(deps, source, depth=0):
        if depth > 30:
            raise ValueError('Dependency nesting exceeded the limit.')
        for name, info in deps.items():
            add('npm', info.get('name', name), info.get('version'), source)
            npm_v1(info.get('dependencies', {}), source, depth+1)

    def sbom_components(rows, source, depth=0):
        if depth > 30:
            raise ValueError('SBOM nesting exceeded the limit.')
        for row in rows:
            if row.get('type') == 'library' or row.get('purl'):
                purl = row.get('purl', '')
                m = re.fullmatch(r'pkg:([^/]+)/([^?#]+)(?:\?[^#]*)?(?:#.*)?', purl)
                if m and m[1] in PURL_ECOSYSTEMS and '@' in m[2]:
                    name, version = m[2].rsplit('@', 1)
                    name = urllib.parse.unquote(name)
                    if m[1] == 'maven':
                        name = name.replace('/', ':')
                    add(PURL_ECOSYSTEMS[m[1]], name, urllib.parse.unquote(version), source)
                else:
                    notes.append(source + ': SBOM component lacks a supported versioned package URL.')
            sbom_components(row.get('components', []), source, depth+1)

    paths = walk(root, notes, stop) if root.is_dir() else [root]
    for path in paths:
        if stop.is_set():
            notes.append('Inventory cancelled.')
            break
        name = path.name
        source = str(path.relative_to(root)) if root.is_dir() else name
        supported = (name.startswith(('requirements', 'constraints')) and path.suffix in ('.txt', '.in')) or name in ('package-lock.json', 'npm-shrinkwrap.json', 'package.json', 'Pipfile.lock', 'poetry.lock', 'uv.lock', 'Cargo.lock', 'go.sum', 'pyproject.toml')
        maybe_sbom = path.suffix.lower() == '.json' and (root.is_file() or 'sbom' in name.lower() or 'bom' == path.stem.lower() or name.endswith('.cdx.json'))
        if name in ('pnpm-lock.yaml', 'yarn.lock', 'Gemfile.lock', 'composer.lock', 'packages.lock.json', 'go.mod'):
            notes.append(source + ': this manifest format is not parsed; supply a CycloneDX JSON SBOM for its resolved dependencies.')
        if not supported and not maybe_sbom:
            continue
        if name == 'package.json' and any((path.parent/x).is_file() for x in ('package-lock.json','npm-shrinkwrap.json')):
            continue
        if name == 'pyproject.toml' and any((path.parent/x).is_file() for x in ('poetry.lock','uv.lock')):
            continue
        try:
            if path.stat().st_size > 4*1024*1024:
                raise ValueError('Manifest exceeds 4 MiB.')
            text = path.read_text(encoding='utf-8-sig')
            manifests.append(source)
            if name.startswith(('requirements', 'constraints')):
                text = re.sub(r'\\\r?\n', ' ', text)
                for line in text.splitlines():
                    line = line.split('#', 1)[0].strip()
                    if not line:
                        continue
                    m = re.fullmatch(r'([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;]+)(?:\s*;[^\n]*|\s+--hash=.*)?', line)
                    if m:
                        add('PyPI', m[1], m[2], source)
                    else:
                        notes.append(source + ': an unpinned requirement, include, URL or option was skipped.')
            elif name in ('package-lock.json', 'npm-shrinkwrap.json'):
                data = json.loads(text)
                if isinstance(data.get('packages'), dict):
                    for location, info in data['packages'].items():
                        if not location:
                            continue
                        if info.get('link'):
                            notes.append(source + ': workspace links are not queried as registry packages.')
                            continue
                        inferred = location.rsplit('node_modules/', 1)[-1]
                        add('npm', info.get('name', inferred), info.get('version'), source)
                else:
                    npm_v1(data.get('dependencies', {}), source)
            elif name == 'package.json':
                data = json.loads(text)
                for group in ('dependencies', 'devDependencies', 'optionalDependencies'):
                    for dep, version in data.get(group, {}).items():
                        add('npm', dep, version, source)
                notes.append(source + ': no npm lockfile; only exact direct versions are checked, without resolved transitive dependencies.')
            elif name == 'Pipfile.lock':
                data = json.loads(text)
                for group in ('default', 'develop'):
                    for dep, info in data.get(group, {}).items():
                        version = info.get('version', '')
                        add('PyPI', dep, version[2:] if version.startswith('==') else '', source)
            elif name in ('poetry.lock', 'uv.lock', 'Cargo.lock', 'pyproject.toml'):
                if tomllib is None:
                    raise ValueError('TOML manifests need Python 3.11 or newer.')
                data = tomllib.loads(text)
                if name == 'pyproject.toml':
                    for dep in data.get('project', {}).get('dependencies', []):
                        m = re.fullmatch(r'([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;]+)(?:\s*;.*)?', dep)
                        if m:
                            add('PyPI', m[1], m[2], source)
                        else:
                            notes.append(source + ': unpinned dependency skipped.')
                    notes.append(source + ': only exact PEP 621 direct dependencies are parsed; supply a lockfile for full coverage.')
                else:
                    for dep in data.get('package', []):
                        origin = dep.get('source', {})
                        registry = (name == 'Cargo.lock' and str(origin).startswith('registry+')) or (name == 'uv.lock' and isinstance(origin, dict) and 'registry' in origin) or (name == 'poetry.lock' and not origin)
                        if registry:
                            add('crates.io' if name == 'Cargo.lock' else 'PyPI', dep.get('name'), dep.get('version'), source)
                        else:
                            notes.append(source + ': local, custom-source or Git dependency skipped.')
            elif name == 'go.sum':
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) == 3:
                        add('Go', parts[0], parts[1].removesuffix('/go.mod'), source)
                notes.append(source + ': go.sum may include unused historical dependencies; verify against the deployed build.')
            else:
                data = json.loads(text)
                if data.get('bomFormat') == 'CycloneDX':
                    sbom_components(data.get('components', []), source)
                else:
                    notes.append(source + ': JSON is not a CycloneDX SBOM.')
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            # Do not include parser messages: they can echo source content/secrets.
            notes.append(source + ': manifest could not be fully parsed within format/size limits.')
            if len(found) >= MAX_PACKAGES:
                break
    return list(found.values()), list(dict.fromkeys(notes)), manifests


def fetch(url, payload=None, timeout=12):
    if url not in (OSV_URL, *KEV_URLS):
        raise ValueError('Unapproved intelligence endpoint.')
    headers = {'Accept': 'application/json', 'User-Agent': 'Ray-i-Security-Hardening-Agent/' + engine.VERSION}
    if payload is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, headers=headers, data=None if payload is None else json.dumps(payload).encode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), engine.NoRedirect())
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(8*1024*1024 + 1)
    if len(raw) > 8*1024*1024:
        raise ValueError('Intelligence response exceeded 8 MiB.')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('Invalid intelligence response.')
    return data


def load_kev():
    for url in KEV_URLS:
        try:
            data = fetch(url)
            rows = data['vulnerabilities']
            if not isinstance(rows, list) or not rows or len(rows) > 20000:
                continue
            entries = {}
            for row in rows:
                cve = row['cveID'].upper()
                if not CVE.fullmatch(cve):
                    raise ValueError('Invalid KEV identifier.')
                entries[cve] = {'dateAdded': clean(row.get('dateAdded'), 40), 'ransomware': clean(row.get('knownRansomwareCampaignUse'), 40), 'action': clean(row.get('requiredAction'), 700)}
            if data.get('count') != len(rows):
                raise ValueError('Incomplete KEV catalog.')
            return {'source': url, 'fetchedAt': now(), 'dateReleased': clean(data.get('dateReleased'), 50), 'catalogVersion': clean(data.get('catalogVersion'), 80), 'entries': entries, 'available': True}
        except Exception:
            continue
    return {'available': False, 'entries': {}, 'error': 'CISA KEV could not be retrieved. Exploitation status is unknown.'}


def normalize_advisory(raw, pkg):
    advisory_id = raw.get('id', '')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,150}', advisory_id):
        raise ValueError('Invalid advisory identifier.')
    aliases = [x.upper() for x in raw.get('aliases', []) if isinstance(x, str) and CVE.fullmatch(x)]
    if CVE.fullmatch(advisory_id):
        aliases.append(advisory_id.upper())
    fixed = []
    for affected in raw.get('affected', []):
        identity = affected.get('package', {})
        candidate = package(identity.get('ecosystem'), identity.get('name'), pkg['version'])
        if candidate and key(candidate) == key(pkg):
            for span in affected.get('ranges', []):
                for event in span.get('events', []):
                    if event.get('fixed'):
                        fixed.append(clean(event['fixed'], 120))
    severity = clean(raw.get('database_specific', {}).get('severity'), 40).upper()
    vectors = [{'type': clean(v.get('type'), 30), 'score': clean(v.get('score'), 200)} for v in raw.get('severity', [])[:5] if isinstance(v, dict)]
    return {'id': advisory_id, 'aliases': sorted(set(aliases)), 'summary': clean(raw.get('summary') or 'Package vulnerability reported by OSV.', 700), 'severity': severity or 'UNSPECIFIED', 'cvss': vectors, 'fixed': sorted(set(fixed))[:20], 'published': clean(raw.get('published'), 50), 'modified': clean(raw.get('modified'), 50)}


def query_package(pkg, stop, deadline):
    result = {'package': {k: pkg[k] for k in ('ecosystem', 'name', 'version')}, 'checkedAt': now(), 'complete': False, 'advisories': []}
    token = None
    seen = set()
    try:
        for _ in range(4):
            if stop.is_set() or time.monotonic() >= deadline:
                result['error'] = 'Lookup cancelled or time budget reached.'
                return result
            payload = {'package': {'name': pkg['name'], 'ecosystem': pkg['ecosystem']}, 'version': pkg['version']}
            if token:
                payload['page_token'] = token
            body = fetch(OSV_URL, payload, max(1, min(12, deadline-time.monotonic())))
            rows = body.get('vulns', [])
            if not isinstance(rows, list):
                raise ValueError('Invalid vulnerability response.')
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError('Invalid advisory.')
                if row.get('withdrawn'):
                    continue
                item = normalize_advisory(row, pkg)
                if item['id'] in seen:
                    continue
                if len(result['advisories']) >= MAX_ADVISORIES:
                    result['error'] = '50-advisory per-package limit reached.'
                    return result
                seen.add(item['id'])
                result['advisories'].append(item)
            token = body.get('next_page_token')
            if not token:
                result['complete'] = True
                return result
        result['error'] = 'Pagination limit reached; additional advisories may exist.'
    except Exception:
        result['error'] = 'OSV lookup failed, timed out, or returned an invalid response.'
    return result


def read_snapshot(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or not path.is_file():
        raise ValueError('Choose an existing absolute path to an exported CVE JSON report or intelligence snapshot.')
    data = read_json(path)
    snapshot = data.get('intelligence', data)
    if snapshot.get('schema') != 'sha-intelligence-v1' or not isinstance(snapshot.get('queries'), list) or len(snapshot['queries']) > MAX_PACKAGES:
        raise ValueError('This is not a supported intelligence snapshot.')
    queries = {}
    for item in snapshot['queries']:
        row = item.get('package', {})
        pkg = package(row.get('ecosystem'), row.get('name'), row.get('version'))
        if not pkg or not isinstance(item.get('advisories'), list) or len(item['advisories']) > MAX_ADVISORIES or not isinstance(item.get('complete'), bool):
            raise ValueError('Invalid package evidence in snapshot.')
        for advisory in item['advisories']:
            if not isinstance(advisory, dict) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,150}', str(advisory.get('id', ''))):
                raise ValueError('Invalid advisory in snapshot.')
            if not all(isinstance(advisory.get(field), list) for field in ('aliases','fixed')):
                raise ValueError('Invalid advisory in snapshot.')
        queries[key(pkg)] = item
    kev = snapshot.get('kev', {})
    if not isinstance(kev.get('entries', {}), dict) or len(kev.get('entries', {})) > 20000:
        raise ValueError('Invalid KEV snapshot.')
    return queries, kev


EXPOSURE_RULES = [
    ('Download piped to a shell', r'(?i)\b(?:curl|wget)\b[^\r\n]{0,500}\|\s*(?:sudo\s+)?(?:ba)?sh\b', 'Pin and verify downloaded artifacts before execution; inspect the download source.'),
    ('Authentication-disable setting', r'(?i)\b(?:disable_auth|auth_disabled|no_auth)\s*[:=]\s*[\x22\x27]?(?:true|1)\b', 'Verify the deployed authentication configuration and restrict network reachability.'),
    ('Privileged container or host socket', r'(?i)(?:\bprivileged\s*:\s*true|/var/run/docker\.sock)', 'Remove unnecessary privileges and Docker socket mounts; isolate model and agent workloads.'),
    ('Dynamic code execution surface', r'\b(?:eval|exec)\s*\(', 'Trace input trust and replace dynamic execution where possible. This pattern is not proof of exploitability.'),
]


def exposure_review(target, stop):
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        return [], {'complete': False, 'rules': 0}, ['Exposure review needs a selected source folder; a manifest/SBOM file alone was supplied. No parent folder was scanned.']
    # Reuse the existing eight static checks and add four exposure-focused rules.
    base = engine.scan_code(str(root))
    findings = []
    for row in base['findings']:
        row = dict(row, name='Exposure indicator · ' + row['name'], area='Unknown-risk indicators', mapping='Heuristic; not a zero-day verdict')
        findings.append(row)
    notes, scanned = [], 0
    extensions = {'.py','.js','.ts','.jsx','.tsx','.json','.yml','.yaml','.toml','.ini','.cfg','.sh','.ps1','.env'}
    for path in walk(root, notes, stop):
        if len(findings) >= 550:
            notes.append('Exposure finding limit reached.')
            break
        if path.suffix.lower() not in extensions and path.name not in ('Dockerfile','.env'):
            continue
        try:
            if path.stat().st_size > 1024*1024:
                notes.append('Exposure check skipped a file over 1 MiB.')
                continue
            text = path.read_text(encoding='utf-8', errors='replace')
            scanned += 1
            for name, pattern, remedy in EXPOSURE_RULES:
                for match in list(re.finditer(pattern, text))[:5]:
                    source = str(path.relative_to(root))
                    line = text.count('\n', 0, match.start())+1
                    item = engine.finding('Exposure indicator · '+name, 'review', f'{source}:{line}. Static pattern; source content omitted. This does not establish an exploitable vulnerability.', remedy, 'Unknown-risk indicators', 'Heuristic; not a zero-day verdict')
                    item.update(file=source, line=line)
                    findings.append(item)
        except OSError:
            notes.append('Exposure check could not read a file.')
    return findings, {'rules': 12, 'filesForAdditionalRules': scanned, 'base': base['coverage'], 'complete': base['status'] == 'complete' and not notes}, notes


def assess(config, progress, stop):
    progress('Reading dependency versions locally…')
    target = config.get('path', '')
    if config.get('mode') == 'package':
        pkg = package(config.get('ecosystem'), config.get('name'), config.get('version'))
        if not pkg:
            raise ValueError('Choose a supported ecosystem and an exact package name and version, without URLs or version ranges.')
        packages, notes, manifests = [pkg], [], []
        target = f"{pkg['ecosystem']} / {pkg['name']} {pkg['version']}"
    else:
        packages, notes, manifests = inventory(target, stop)
    online = config.get('online') is True
    queries, kev = {}, {'available': False, 'entries': {}}
    if online:
        progress('Downloading the public CISA known-exploited catalog…')
        if not stop.is_set():
            kev = load_kev()
        deadline = time.monotonic()+180
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = {pool.submit(query_package, p, stop, deadline): p for p in packages}
            for future in concurrent.futures.as_completed(jobs):
                queries[key(jobs[future])] = future.result()
                progress(f'Checked {len(queries)} of {len(packages)} package versions against OSV…')
    elif config.get('snapshotPath'):
        queries, kev = read_snapshot(config['snapshotPath'])
        notes.append('Offline snapshot is user-supplied evidence, not independently authenticated. Only matching exact queries are reused.')
    findings, used_queries, checks = [], [], []
    unknown_count = complete_count = 0
    kev_ready = kev.get('available') is True and isinstance(kev.get('entries'), dict) and bool(kev['entries'])
    kev_stale = not kev_ready or old(kev.get('dateReleased')) or old(kev.get('fetchedAt'))
    if not kev_ready or kev_stale:
        findings.append(engine.finding('Known-exploitation data unavailable or stale', 'unknown', 'CISA KEV could not be retrieved or its release/download is older than seven days (or has an invalid date).', 'Repeat with public lookups enabled and review vendor advisories. Absence from KEV is not proof of no exploitation.', 'Threat intelligence'))
    for pkg in packages:
        result = queries.get(key(pkg))
        usable = bool(result and result.get('complete') is True and not old(result.get('checkedAt')))
        advisories = result.get('advisories', []) if result else []
        if result:
            used_queries.append(result)
        if usable:
            complete_count += 1
        else:
            unknown_count += 1
        checks.append(dict(pkg, status='checked' if usable else 'unknown', advisories=len(advisories), checkedAt=result.get('checkedAt') if result else None))
        if not usable:
            reason = result.get('error') if result else 'No exact package/version query exists in the selected evidence.'
            findings.append(engine.finding(f"CVE coverage unknown · {pkg['name']} {pkg['version']}", 'unknown', reason or 'Evidence is incomplete, older than seven days, or has an invalid date.', 'Re-run a current lookup. A missing or stale result is not a pass.', 'CVE coverage'))
        for item in advisories:
            aliases = [str(x).upper() for x in item.get('aliases', []) if CVE.fullmatch(str(x))]
            if CVE.fullmatch(str(item['id'])):
                aliases.append(item['id'].upper())
            hits = [cve for cve in set(aliases) if cve in kev.get('entries', {})]
            title_id = ', '.join(sorted(set(aliases))) or item['id']
            kev_text = ('CISA KEV lists ' + ', '.join(hits) + ' as exploited in the wild.' + (' Catalog evidence is stale.' if kev_stale else '')) if hits else ('No matching CVE identifier is listed in this retrieved KEV catalog; this is not proof of no exploitation.' if kev_ready else 'Exploitation status unknown: KEV unavailable.')
            evidence = f"{pkg['ecosystem']} / {pkg['name']} {pkg['version']} · {pkg['source']}\nOSV advisory {item['id']}: {clean(item.get('summary'),700)}\nProvider severity: {clean(item.get('severity'),40)}. {kev_text}\nPackage-version match only; deployed use and exploitability are not established."
            fixes = ', '.join(clean(x,120) for x in item.get('fixed', [])[:20])
            remedy = ('Provider fix boundaries: ' + fixes + '. Verify the correct release branch and all applicable advisories before upgrading.') if fixes else 'Review the linked advisory and vendor mitigation guidance; no fixed version was supplied for this package.'
            if hits:
                remedy = 'Prioritize remediation: known exploitation reported. ' + remedy
            row = engine.finding(('KNOWN EXPLOITED · ' if hits else 'CVE / advisory · ') + title_id + ' · ' + pkg['name'], 'attention', evidence, remedy, 'Known vulnerabilities', 'CISA KEV' if hits else 'OSV')
            row.update(package=pkg, advisoryId=item['id'], cves=sorted(set(aliases)), knownExploited=bool(hits), kev=[dict(cve=c, **kev['entries'][c]) for c in hits], severity=clean(item.get('severity'),40), cvss=item.get('cvss', []), fixedVersions=item.get('fixed', []), reference='https://osv.dev/vulnerability/'+item['id'], published=item.get('published'), modified=item.get('modified'), checkedAt=result.get('checkedAt'), stale=not usable)
            findings.append(row)
    if not packages:
        findings.append(engine.finding('No supported exact dependency versions found', 'unknown', 'No packages could be matched to the vulnerability database.', 'Supply a supported lockfile, pinned requirements, CycloneDX SBOM, or a manual exact package/version.', 'CVE coverage'))
    elif complete_count and not any(c['advisories'] for c in checks):
        findings.append(engine.finding('No advisories returned for checked package versions', 'review', f'OSV returned no advisories for {complete_count} current complete package queries. {unknown_count} package queries remain unknown.', 'This is limited database evidence, not proof the software is safe or free of zero-days.', 'CVE coverage'))
    exposure = None
    if config.get('exposure') is True and config.get('mode') != 'package' and not stop.is_set():
        progress('Reviewing local exposure indicators without executing code…')
        extra, exposure, exposure_notes = exposure_review(config.get('path'), stop)
        findings.extend(extra)
        notes.extend(exposure_notes)
    findings.append(engine.finding('Undisclosed zero-day coverage', 'unknown', 'Unknown or undisclosed vulnerabilities cannot be reliably identified by a CVE lookup. Static exposure indicators and bounded AI boundary tests do not establish that a zero-day exists or is absent.', 'Review exposure indicators, run the AI endpoint boundary tests, restrict privileges and reachable services, and repeat CVE checks as advisories are published.', 'Zero-day limits'))
    if notes:
        findings.append(engine.finding('Inventory and evidence coverage notes', 'unknown' if any('Offline snapshot' not in n for n in notes) else 'review', '\n'.join(notes[:80]), 'Resolve unsupported, unpinned, oversized or unreadable inputs and verify dependencies against the deployed build.', 'CVE coverage'))
    count_before = len(findings)
    findings.sort(key=lambda x: (not x.get('knownExploited', False), x.get('status') != 'attention'))
    if count_before > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS-1] + [engine.finding('Finding limit reached', 'unknown', f'{count_before} items exceeded the 1,500-finding report limit.', 'Scan smaller dependency sets.', 'Coverage')]
    incomplete = not packages or unknown_count > 0 or kev_stale or any('Offline snapshot' not in n for n in notes) or count_before > MAX_FINDINGS or (exposure and not exposure['complete'])
    return {'schema': 'sha-report-v1', 'type': 'CVE & exposure', 'createdAt': now(), 'target': target, 'status': 'cancelled' if stop.is_set() else ('partial' if incomplete else 'complete'), 'findings': findings,
            'coverage': {'packagesInventoried': len(packages), 'currentCompleteQueries': complete_count, 'unknownQueries': unknown_count, 'matchedAdvisories': sum(c['advisories'] for c in checks), 'knownExploitedMatches': sum(bool(f.get('knownExploited')) for f in findings), 'manifests': len(manifests), 'exposure': exposure, 'zeroDayDetection': 'not established'},
            'dependencies': checks, 'dependencyManifests': manifests, 'intelligence': {'schema': 'sha-intelligence-v1', 'mode': 'online' if online else 'offline', 'createdAt': now(), 'queries': used_queries, 'kev': kev},
            'limitations': ['Checks supported exact open-source package versions against OSV; reports package matches, not proven reachability or exploitation.', 'Windows/macOS OS patch CVEs, Linux distribution backports, firmware, drivers, containers as images, and model-weight backdoors are not covered by these package checks.', 'Source code, secrets, local paths and model contents are not sent to OSV. Public lookups disclose only package ecosystem, name, version and pagination tokens. CISA catalog downloads carry no inventory.', 'CISA KEV means known exploitation, not necessarily a zero-day or an exploit on this system. Not listed does not mean unexploited.', 'Undisclosed zero-days cannot be certified absent. Exposure rules are heuristic review leads; no exploit code, scanned application, or model file is executed.', 'At most 200 unique package versions, four concurrent requests, 180 seconds for OSV, four pages and 50 advisories per package, and 1,500 reported findings. Manifests over 4 MiB and ignored build/dependency folders are skipped.', 'Versions come from selected manifests or supplied SBOM/manual inventory and may differ from deployed software. Conditional, development and historical dependencies can produce non-applicable matches.', 'Evidence older than seven days is marked unknown. Offline snapshots reuse only exact saved queries and are not authenticated or a complete offline CVE database. Export JSON to retain evidence.']}
