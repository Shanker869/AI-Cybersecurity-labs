# COPPERFOX Infrastructure Update — October 2026

> Fictional threat report written for a home lab.

Following public reporting, COPPERFOX rotated its command-and-control infrastructure. New C2 servers
were observed at 198.51.100.200 and on the domain secure-ledger-api[.]xyz. The group continues to use
FOXLOADER but has added string encryption to evade static signatures (T1027).

The October wave shifted from Excel attachments to HTML smuggling: emails link to a page on
docs-share-view[.]site that assembles a ZIP file in the browser (T1027.006). The ZIP contains an LNK
file that runs the loader (T1204.002).

We observed the actor clearing Windows event logs (T1070.001) before exfiltrating archived data over
the existing C2 channel (T1041). Defenders should block the new infrastructure, hunt for LNK files
in ZIP archives in user Downloads folders, and alert on wevtutil cl or Security log clear events
(Event ID 1102).
