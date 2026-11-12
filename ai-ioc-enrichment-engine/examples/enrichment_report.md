# IOC Enrichment Report

Input: `data/sample_phishing_report.txt` · Providers: local_feed · AI: `none`

## Analyst note

11 indicators enriched: 7 malicious, 1 suspicious, 3 clean/unknown. Block now: 44d88612fea8a8f36de82e1278abb02f, 9f2b5c1e0f4b3a7d8e6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706, 203[.]0[.]113[.]66, hxxps[://]login-micros0ft[.]top/auth/office365?session=8812, hxxp[://]cdn-update[.]xyz/upd[.]exe, billing@secure-paypa1[.]com. Patch priority: CVE-2023-23397. ATT&CK hints: T1071, T1071.001, T1105, T1110, T1190, T1486, T1566, T1595. Search SIEM/EDR telemetry for these indicators over the last 30 days to scope exposure.

## Indicators

| Verdict | Score | Type | Indicator (defanged) | Tags | ATT&CK hints |
|---|---|---|---|---|---|
| malicious | 100 | md5 | `44d88612fea8a8f36de82e1278abb02f` | eicar-test-file |  |
| malicious | 100 | sha256 | `9f2b5c1e0f4b3a7d8e6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706` | loader;ransomware | T1105;T1486 |
| malicious | 95 | ipv4 | `203[.]0[.]113[.]66` | c2;cobalt-strike | T1071;T1071.001 |
| malicious | 90 | url | `hxxps[://]login-micros0ft[.]top/auth/office365?session=8812` | credential-harvest;phishing | T1566 |
| malicious | 85 | url | `hxxp[://]cdn-update[.]xyz/upd[.]exe` | loader;malware-delivery | T1105 |
| malicious | 80 | email | `billing@secure-paypa1[.]com` | phishing | T1566 |
| malicious | 75 | cve | `CVE-2023-23397` | exploit;known-exploited;outlook | T1190 |
| suspicious | 60 | ipv4 | `198[.]51[.]100[.]23` | brute-force;scanner | T1110;T1595 |
| unknown | 0 | email | `bounce@mailer-cdn[.]top` |  |  |
| unknown | 0 | email | `support@contoso[.]com` |  |  |
| clean | 0 | url | `hxxps[://]www[.]microsoft[.]com/privacy` | allowlist |  |