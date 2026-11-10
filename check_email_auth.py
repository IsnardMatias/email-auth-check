"""Audit SPF and DMARC for a list of domains. Needs dnspython (pip install dnspython).

Usage:
    python check_email_auth.py example.com other.org
    python check_email_auth.py --file domains.txt --csv

Exit code: 0 every domain passes, 1 at least one domain has a problem.
"""
import argparse
import csv
import re
import sys

import dns.exception
import dns.resolver

LOOKUP_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}  # RFC 7208 4.6.4
MAX_LOOKUPS = 10

resolver = dns.resolver.Resolver()
resolver.lifetime = 5


def txt(name):
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    return [b"".join(r.strings).decode(errors="replace") for r in answers]


def spf_record(domain):
    records = [r for r in txt(domain) if r.lower().startswith("v=spf1")]
    return records


def count_lookups(domain, depth=0, seen=None):
    """Count DNS lookups an SPF check triggers, following include and redirect. Stops early past the limit."""
    seen = seen if seen is not None else set()
    if depth > 10 or domain in seen:
        return 0
    seen.add(domain)
    records = spf_record(domain)
    if len(records) != 1:
        return 0
    total = 0
    for term in records[0].split()[1:]:
        mech = term.lower().lstrip("+-~?")
        name = re.split(r"[:/=]", mech, maxsplit=1)[0]
        if name in LOOKUP_TERMS:
            total += 1
            if name in ("include", "redirect"):
                target = re.split(r"[:=]", mech, maxsplit=1)[1]
                total += count_lookups(target, depth + 1, seen)
        if total > MAX_LOOKUPS:
            break
    return total


def all_qualifier(record):
    for term in record.split()[1:]:
        if term.lower().lstrip("+-~?") == "all":
            return term[0] + "all" if term[0] in "+-~?" else "+all"
    return None


def parse_tags(record):
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def audit(domain):
    row = {"domain": domain, "spf": "missing", "spf_lookups": "", "dmarc": "missing", "rua": "", "problems": []}

    spf = spf_record(domain)
    if len(spf) > 1:
        row["spf"] = "multiple records"
        row["problems"].append("more than one SPF record: receivers treat this as an error")
    elif spf:
        row["spf"] = all_qualifier(spf[0]) or "no all"
        lookups = count_lookups(domain)
        row["spf_lookups"] = lookups
        if row["spf"] == "+all":
            row["problems"].append("+all lets anyone send as you")
        if lookups > MAX_LOOKUPS:
            row["problems"].append(f"SPF needs {lookups}+ DNS lookups (limit is 10): it may fail as permerror")
    else:
        row["problems"].append("no SPF record")

    dmarc = [r for r in txt(f"_dmarc.{domain}") if r.lower().replace(" ", "").startswith("v=dmarc1")]
    if len(dmarc) > 1:
        row["dmarc"] = "multiple records"
        row["problems"].append("more than one DMARC record: receivers ignore DMARC entirely")
    elif dmarc:
        tags = parse_tags(dmarc[0])
        row["dmarc"] = "p=" + tags.get("p", "?")
        row["rua"] = "yes" if tags.get("rua") else "no"
        if tags.get("p", "").lower() == "none":
            row["problems"].append("DMARC p=none: spoofed mail is still delivered")
        if not tags.get("rua"):
            row["problems"].append("no rua: you get no reports, so you can't safely tighten the policy")
    else:
        row["problems"].append("no DMARC record")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domains", nargs="*")
    ap.add_argument("--file")
    ap.add_argument("--csv", action="store_true")
    args = ap.parse_args()

    domains = list(args.domains)
    if args.file:
        with open(args.file) as f:
            domains += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not domains:
        ap.error("give at least one domain or --file")

    rows = [audit(d) for d in domains]
    if args.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["domain", "spf", "spf_lookups", "dmarc", "rua", "problems"])
        for r in rows:
            w.writerow([r["domain"], r["spf"], r["spf_lookups"], r["dmarc"], r["rua"], " | ".join(r["problems"])])
    else:
        for r in rows:
            print(f'{r["domain"]:<24} SPF {r["spf"]:<8} lookups {str(r["spf_lookups"]):<3} DMARC {r["dmarc"]:<14} rua {r["rua"] or "-"}')
            for p in r["problems"]:
                print(f"    - {p}")
    sys.exit(1 if any(r["problems"] for r in rows) else 0)


if __name__ == "__main__":
    main()
