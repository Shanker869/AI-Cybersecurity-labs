# Example session (LLM_PROVIDER=none, extractive fallback)

```
Q: What scheduled task does FOXLOADER use and where does it beacon?

The loader, tracked as FOXLOADER (SHA256 4b7e1c0d9a8f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a2918070f6e), is side-loaded by a signed binary and persists through a scheduled task named "OneDriveSyncCheck" (T1053.005). [1] Scheduled tasks created by users in the Finance OU [2] The group continues to use FOXLOADER but has added string encryption to evade static signatures (T1027). [3]

Sources:
 *[1] copperfox_q3_report.md (copperfox_q3_report#1, bm25=3.55)
 *[2] copperfox_q3_report.md (copperfox_q3_report#2, bm25=1.23)
 *[3] copperfox_infra_update.md (copperfox_infra_update#0, bm25=1.06)

copperfox_infra_update.md: 162 words. Techniques: T1027, T1027.006, T1041, T1070.001, T1204.002. IOCs: 3. CVEs: none. 

Extracted intel:
{
  "ipv4-addr": [
    "198.51.100.200"
  ],
  "domain-name": [
    "docs-share-view.site",
    "secure-ledger-api.xyz"
  ],
  "sha256": [],
  "md5": [],
  "attack_techniques": [
    "T1027",
    "T1027.006",
    "T1041",
    "T1070.001",
    "T1204.002"
  ],
  "cves": []
}
```
