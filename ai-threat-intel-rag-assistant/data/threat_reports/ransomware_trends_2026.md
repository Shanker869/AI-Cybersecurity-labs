# Ransomware Trends Brief — 2026 H2

> Fictional brief written for a home lab.

Ransomware affiliates increasingly exploit edge devices such as VPNs and firewalls for initial access
(T1190) instead of phishing. Before encryption, affiliates commonly delete volume shadow copies with
vssadmin (T1490) and disable security tools (T1562.001). Data is usually stolen before encryption to
support double extortion (T1486, T1567).

Recommended controls: patch internet-facing appliances within 72 hours of a known-exploited
vulnerability being published, keep offline immutable backups, enforce MFA on remote access, and alert
on vssadmin delete shadows commands. A sample of the BLACKTIDE-LAB locker has MD5
5d41402abc4b2a76b9719d911017c592 (test value).
