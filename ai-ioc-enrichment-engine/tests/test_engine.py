from pathlib import Path

from ioc_engine.cli import main
from ioc_engine.enrich import combine, enrich_all
from ioc_engine.extract import IOC, defang, extract, refang
from ioc_engine.providers import LocalFeed, ProviderResult

DATA = Path(__file__).resolve().parents[1] / "data"


def kinds(text, **kw):
    return {(i.type, i.value) for i in extract(text, **kw)}


def test_refang_variants():
    assert refang("hxxps://evil[.]com and 1.2.3(.)4 and a[@]b[dot]com") == "https://evil.com and 1.2.3.4 and a@b.com"


def test_defang_roundtrip():
    assert defang("https://evil.com/x") == "hxxps[://]evil[.]com/x"
    assert refang(defang("https://evil.com/x")) == "https://evil.com/x"
    assert defang("CVE-2024-3400") == "CVE-2024-3400"


def test_extraction_types_and_filters():
    found = kinds("Dropped invoice.docm from evil.top; beacon 8.8.8.8 and 10.0.0.5; "
                  "hash D41D8CD98F00B204E9800998ECF8427E; CVE-2024-3400; mail x@bad.xyz")
    assert ("domain", "evil.top") in found and ("ipv4", "8.8.8.8") in found
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in found and ("cve", "CVE-2024-3400") in found
    assert not any(v == "invoice.docm" for _, v in found)       # file names are not domains
    assert ("ipv4", "10.0.0.5") not in found                    # private IPs dropped by default
    assert ("ipv4", "10.0.0.5") in kinds("10.0.0.5", include_private=True)
    assert ("domain", "bad.xyz") not in found                   # domain inside email is not duplicated


def test_combine_scoring():
    e = combine(IOC("ipv4", "1.2.3.4"), [ProviderResult("virustotal", 80, "malicious", ["c2"]),
                                         ProviderResult("abuseipdb", 60, "suspicious", ["brute-force"])])
    assert e.verdict == "malicious" and e.score == 88 and {"T1071", "T1110"} <= set(e.techniques)
    assert combine(IOC("ipv4", "1.2.3.4"), [ProviderResult("otx", 0, "unknown")]).verdict == "unknown"


def test_local_feed_matches_url_and_email_hosts():
    feed = LocalFeed(DATA / "local_intel.json")
    items = enrich_all([IOC("url", "https://login-micros0ft.top/a"), IOC("email", "x@secure-paypa1.com")], [feed])
    assert all(i.verdict == "malicious" for i in items)


def test_cli_end_to_end(tmp_path):
    main(["enrich", str(DATA / "sample_phishing_report.txt"), "--outdir", str(tmp_path), "--no-cache"])
    csv_text = (tmp_path / "enriched_iocs.csv").read_text()
    assert "203[.]0[.]113[.]66" in csv_text and "malicious" in csv_text
    assert "Analyst note" in (tmp_path / "enrichment_report.md").read_text()
