"""Offline ModelAudit worker. No model execution and no cloud credentials."""
import json
import os
from pathlib import Path
import sys


def main():
    config=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    os.environ.update(PROMPTFOO_DISABLE_TELEMETRY='1',MODELAUDIT_DISABLE_TELEMETRY='1',DO_NOT_TRACK='1',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',AWS_EC2_METADATA_DISABLED='true')
    from skillspector_worker import install_network_guard
    install_network_guard()
    from modelaudit.core import scan_model_directory_or_file
    from modelaudit.rules import RuleRegistry
    from modelaudit import __version__
    result=scan_model_directory_or_file(config['path'],timeout=180,max_file_size=8*1024**3,max_total_size=16*1024**3,
        skip_file_types=False,cache_enabled=False,use_cache=False,max_directory_owner_snapshot_entries=10000)
    data=result.model_dump(mode='json')
    issues=[]
    for item in data.get('issues',[])[:1000]:
        code=item.get('rule_code') or ''
        rule=RuleRegistry.get_rule(code) if code else None
        # Never copy arbitrary messages, details, secret snippets or payloads into app reports.
        issues.append({'code':code,'severity':item.get('severity'),'name':rule.name if rule else 'Model scanner finding',
                       'description':rule.description if rule else 'The scanner reported an issue; source payload text is omitted.',
                       'location':str(item.get('location') or '')[:700]})
    output={'version':__version__,'issues':issues,'issueCount':len(data.get('issues',[])),
        'filesScanned':data.get('files_scanned',0),'bytesScanned':data.get('bytes_scanned',0),'checks':data.get('total_checks',0),
        'success':data.get('success') is True,'hasErrors':bool(data.get('has_errors')),'scanners':data.get('scanner_names',[]),
        'duration':data.get('duration'),'aggregateHash':data.get('content_hash')}
    Path(config['output']).write_text(json.dumps(output),encoding='utf-8')


if __name__=='__main__':
    main()
