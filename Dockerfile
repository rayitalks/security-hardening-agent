FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SHA_CONTAINER=1
ENV SHA_TRIVY_CACHE=/data/trivy
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential clamav clamav-freshclam libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY vendor/ ./vendor/
COPY constraints-skillspector.txt ./
RUN python -m pip install --no-cache-dir --find-links ./vendor -c constraints-skillspector.txt ./vendor/skillspector-2.12.0-py3-none-any.whl && apt-get purge -y build-essential && apt-get autoremove -y
COPY install_trivy.py ./
RUN python install_trivy.py
COPY install_model_tools.py constraints-model.txt ./
RUN python install_model_tools.py
COPY install_audit_tools.py install_gitleaks.py ./
RUN python install_audit_tools.py
COPY app.py engine.py collector.py scan.ps1 index.html skillspector_integration.py skillspector_worker.py vulnerabilities.py containers.py container_collect.py model_tools.py model_worker.py packet_worker.py traffic.py actions.py agent_scanner.py ./
COPY security_store.py asset_registry.py guardrails.py mcp_security.py runtime_gateway.py redteam.py deployment_audits.py integrity_monitor.py remote_probe.py workspace.js ./
COPY pdf_source_worker.py ./
COPY vm_scan.py vm_remote.py vm_hyperv.ps1 auth_events.ps1 behavior_rules.py inference_metrics.py monitor_worker.py live_monitor.py malware_intel.py audit_trail.py engagements.py defense_ops.py team_suite.py purple_team.py security_ci.py team-workspace.js monitor.html ./
COPY audit_export.py agent_client.py ./
COPY pqc_tools.py pqc_worker.cjs pqc_keytool.py government_guidance.json ./
COPY scan_center.py ./
COPY model_weights.py weight_worker.py model_behavior.py model-assurance.js inference_providers.py endpoint-providers.js ./
COPY inference_providers.py endpoint-providers.js ./
COPY licenses/ ./licenses/
RUN useradd --create-home --uid 10001 assessor && mkdir -p /data/trivy /data/clamav && chown -R assessor:assessor /data
USER assessor
EXPOSE 8765 8766
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/environment',timeout=3)"
CMD ["/app/.audit-runtime/bin/python", "app.py"]
