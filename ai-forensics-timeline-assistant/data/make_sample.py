"""Write a synthetic Plaso l2tcsv super-timeline: an insider copies HR data to USB and cloud, then cleans up.

Host, user and files are fictional. Ordinary activity (Office, Chrome, logons) is mixed in as noise.
"""
import csv
from pathlib import Path

HOST, USER = "LAPTOP-HR02", "dmorgan"
COLS = ["date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host", "short", "desc",
        "version", "filename", "inode", "notes", "format", "extra"]
rows = []


def add(date, time, source, stype, typ, desc, filename="-", macb="....", user=USER):
    rows.append({"date": date, "time": time, "timezone": "UTC", "MACB": macb, "source": source,
                 "sourcetype": stype, "type": typ, "user": user, "host": HOST, "short": desc[:80], "desc": desc,
                 "version": "2", "filename": filename, "inode": "-", "notes": "-", "format": "-", "extra": "-"})


D1, D2 = "10/28/2026", "10/29/2026"
# --- normal workday -----------------------------------------------------------------------------
add(D1, "08:55:12", "EVT", "WinEVTX", "Content Modification Time",
    "[4624 / 0x1210] Security: An account was successfully logged on. Account: dmorgan Logon Type: 2",
    r"C:\Windows\System32\winevt\Logs\Security.evtx")
add(D1, "08:56:03", "PREFETCH", "WinPrefetch", "Last Time Executed", "Prefetch [OUTLOOK.EXE] was executed - run count 214",
    r"C:\Windows\Prefetch\OUTLOOK.EXE-1A2B3C4D.pf")
add(D1, "09:10:44", "WEBHIST", "Chrome History", "Last Visited Time",
    "https://intranet.contoso-hr.local/payroll (Payroll portal) [count: 12]", r"C:\Users\dmorgan\AppData\Local\Google\Chrome\User Data\Default\History")
add(D1, "11:22:09", "PREFETCH", "WinPrefetch", "Last Time Executed", "Prefetch [EXCEL.EXE] was executed - run count 98",
    r"C:\Windows\Prefetch\EXCEL.EXE-5E6F7A8B.pf")
add(D1, "14:31:50", "FILE", "NTFS $MFT", "Creation Time", r"C:\Users\dmorgan\Documents\Q4_headcount_plan.xlsx", macb="..CB")
# --- after hours: staging and exfiltration ------------------------------------------------------
add(D1, "18:42:17", "WEBHIST", "Chrome History", "Last Visited Time", "https://mega.nz/register (MEGA) [count: 1]",
    r"C:\Users\dmorgan\AppData\Local\Google\Chrome\User Data\Default\History")
add(D1, "18:44:02", "WEBHIST", "Chrome History", "File Downloaded",
    r"Chrome download: https://downloads.rclone.org/rclone-current-windows-amd64.zip -> C:\Users\dmorgan\Downloads\rclone.zip (download complete)",
    r"C:\Users\dmorgan\AppData\Local\Google\Chrome\User Data\Default\History")
add(D1, "18:47:31", "PREFETCH", "WinPrefetch", "Last Time Executed", "Prefetch [RCLONE.EXE] was executed - run count 3",
    r"C:\Windows\Prefetch\RCLONE.EXE-9C8D7E6F.pf")
add(D1, "18:50:12", "PREFETCH", "WinPrefetch", "Last Time Executed", "Prefetch [7Z.EXE] was executed - run count 1",
    r"C:\Windows\Prefetch\7Z.EXE-11223344.pf")
add(D1, "18:51:40", "FILE", "NTFS $MFT", "Creation Time", r"C:\Users\dmorgan\Documents\hr_export_full.7z (412 MB)", macb="..CB")
add(D1, "18:58:05", "REG", "Registry Key", "First Connection Time",
    r"[HKLM\SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001] Serial: 4C530001 FriendlyName: SanDisk Cruzer Blade USB Device",
    r"C:\Windows\System32\config\SYSTEM")
add(D1, "18:58:06", "REG", "Registry Key", "Content Modification Time",
    r"[HKLM\SYSTEM\MountedDevices] \DosDevices\E: -> USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade", r"C:\Windows\System32\config\SYSTEM")
add(D1, "19:01:33", "LNK", "Windows Shortcut", "Content Modification Time",
    r"[Empty description] Local path: E:\hr_export_full.7z Drive type: Removable Volume serial: 0x6A2F11C0",
    r"C:\Users\dmorgan\AppData\Roaming\Microsoft\Windows\Recent\hr_export_full.7z.lnk")
add(D1, "19:05:48", "PREFETCH", "WinPrefetch", "Last Time Executed", "Prefetch [SDELETE64.EXE] was executed - run count 1",
    r"C:\Windows\Prefetch\SDELETE64.EXE-AABBCCDD.pf")
add(D1, "19:07:10", "EVT", "WinEVTX", "Content Modification Time",
    "[1102 / 0x044e] Security: The audit log was cleared. Subject: dmorgan", r"C:\Windows\System32\winevt\Logs\Security.evtx")
add(D1, "19:08:22", "PREFETCH", "WinPrefetch", "Last Time Executed", "Prefetch [WEVTUTIL.EXE] was executed - run count 2",
    r"C:\Windows\Prefetch\WEVTUTIL.EXE-55667788.pf")
add(D1, "19:09:01", "EVT", "WinEVTX", "Content Modification Time",
    "[104 / 0x0068] System: The System log file was cleared.", r"C:\Windows\System32\winevt\Logs\System.evtx")
# --- next morning: normal ------------------------------------------------------------------------
add(D2, "08:49:40", "EVT", "WinEVTX", "Content Modification Time",
    "[4624 / 0x1210] Security: An account was successfully logged on. Account: dmorgan Logon Type: 2",
    r"C:\Windows\System32\winevt\Logs\Security.evtx")
add(D2, "09:02:15", "PREFETCH", "WinPrefetch", "Last Time Executed", "Prefetch [CHROME.EXE] was executed - run count 640",
    r"C:\Windows\Prefetch\CHROME.EXE-DEADBEEF.pf")
add(D2, "09:15:03", "WEBHIST", "Chrome History", "Last Visited Time", "https://www.linkedin.com/jobs/ (Jobs) [count: 4]",
    r"C:\Users\dmorgan\AppData\Local\Google\Chrome\User Data\Default\History")

rows.sort(key=lambda r: (r["date"], r["time"]))
out = Path(__file__).parent / "sample_timeline_l2t.csv"
with out.open("w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=COLS); w.writeheader(); w.writerows(rows)
print(f"wrote {len(rows)} events -> {out}")
