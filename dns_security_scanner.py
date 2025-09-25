import argparse
import dns.resolver
import json

def query_dns(domain, record_type, lifetime=5):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=lifetime)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []

def get_txt_records(domain, lifetime=5):
    """Ambil TXT records dengan parsing string agar tidak kosong."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=lifetime)
        txt_records = []
        for rdata in answers:
            # Join semua string dalam record TXT (bisa pecah jadi beberapa potongan)
            txt_records.append("".join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings]))
        return txt_records
    except Exception:
        return []

def check_security(records, domain):
    security = {"SPF": "MISSING", "DKIM": "MISSING", "DMARC": "MISSING"}

    # SPF
    for txt in records.get("TXT", []):
        if "v=spf1" in txt.lower():
            security["SPF"] = "OK"

    # DKIM: coba common selector 'default' dan 'google'
    selectors = ["default", "google"]
    for sel in selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        dkim_records = query_dns(dkim_domain, "TXT")
        if dkim_records:
            security["DKIM"] = "OK"
            break

    # DMARC
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = query_dns(dmarc_domain, "TXT")
    if dmarc_records:
        security["DMARC"] = "OK"

    return security

def collect_records(domain):
    types = ["A", "AAAA", "MX", "NS", "CNAME", "SOA"]
    out = {}
    for t in types:
        out[t] = query_dns(domain, t)

    # TXT pakai parser khusus biar lebih akurat
    out["TXT"] = get_txt_records(domain)

    return out

def print_table(rows, headers):
    # Simple column widths
    widths = [max(len(str(r[i])) for r in rows + [headers]) + 2 for i in range(len(headers))]
    # header
    line = "|".join(h.center(widths[i]) for i,h in enumerate(headers))
    sep = "+".join("-" * widths[i] for i in range(len(headers)))
    print(sep)
    print(line)
    print(sep)
    for r in rows:
        print("|".join(str(r[i]).center(widths[i]) for i in range(len(headers))))
    print(sep)

def main():
    parser = argparse.ArgumentParser(description="DNS Security Scanner (no-tabulate)")
    parser.add_argument("-d", "--domain", help="Single domain to scan")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    args = parser.parse_args()

    domains = []
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                domains = [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            print(f"File not found: {args.file}")
            return
    elif args.domain:
        domains = [args.domain]
    else:
        print("Please provide -d <domain> or -f <domains.txt>")
        return

    results = []
    rows = []
    for dom in domains:
        print(f"\nScanning: {dom}")
        recs = collect_records(dom)
        sec = check_security(recs, dom)
        results.append({"domain": dom, "records": recs, "security": sec})
        rows.append([dom, sec["SPF"], sec["DKIM"], sec["DMARC"]])

    # Print simple table
    print()
    print_table(rows, ["Domain", "SPF", "DKIM", "DMARC"])

    # Save JSON
    with open("dns_security_report.json", "w", encoding="utf-8") as out:
        json.dump(results, out, indent=4)
    print("\nSaved output -> dns_security_report.json")

if __name__ == "__main__":
    main()
