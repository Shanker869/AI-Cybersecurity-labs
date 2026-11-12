#!/usr/bin/env bash
# Creates and pushes all lab repos to github.com/Shanker869. Requires: git, gh (gh auth login).
set -euo pipefail
OWNER="Shanker869"
declare -A DESC=(
  [ai-windows-auth-log-analyzer]="AI-assisted Windows authentication log analyzer: brute force, password spray, RDP and log-clearing detections mapped to MITRE ATT&CK"
  [ai-soc-alert-triage]="AI SOC alert triage assistant: correlates Wazuh/Sentinel/CrowdStrike alerts, scores incidents, drafts investigations"
  [ai-ioc-enrichment-engine]="IOC extraction and enrichment (VirusTotal, AbuseIPDB, OTX) with risk scoring and AI analyst notes"
  [ai-threat-intel-rag-assistant]="Threat intelligence RAG assistant with verified citations and STIX 2.1 export for OpenCTI/MISP"
  [ai-grc-risk-assessment-tool]="Prowler/ScoutSuite findings to a risk register mapped to NIST CSF 2.0, ISO 27001, SOC 2 and 800-53"
  [ai-forensics-timeline-assistant]="AI-assisted Plaso/Timesketch forensic timeline analysis with ATT&CK mapping and chain of custody"
)
gh auth status >/dev/null || { echo "Run: gh auth login"; exit 1; }
for repo in "${!DESC[@]}" "$OWNER"; do
  [ -d "$repo" ] || { echo "skip $repo (folder missing)"; continue; }
  echo "==> $repo"
  pushd "$repo" >/dev/null
  [ -d .git ] || git init -q -b main
  git add .
  git diff --cached --quiet || git commit -q -m "Initial commit: ${repo}"
  if gh repo view "$OWNER/$repo" >/dev/null 2>&1; then
    git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$OWNER/$repo.git"
    git push -u origin main
  else
    gh repo create "$OWNER/$repo" --public --source=. --push --description "${DESC[$repo]:-GitHub profile}"
  fi
  [ "$repo" != "$OWNER" ] && gh repo edit "$OWNER/$repo" --add-topic cybersecurity,python,llm,home-lab,mitre-attack >/dev/null || true
  popd >/dev/null
done
echo "Done. Visit https://github.com/$OWNER"
