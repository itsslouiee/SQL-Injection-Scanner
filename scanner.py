import time
from parser import extract_targets
from detectors import run_all_detectors


def print_banner():
    print(f"\n{'='*70}")
    print("SQL INJECTION SCANNER")
    print(f"{'='*70}")


def print_target_header(target, index, total):
    print(f"\n{'='*70}")
    print(f"[*] Testing {target['source']} ({index}/{total})")
    print(f"{'='*70}")
    print(f"    Method: {target['method'].upper()}")
    print(f"    URL:    {target['url']}")
    print(f"    Fields: {', '.join(target['fields'])}")
    if target.get("hidden_fields"):
        print(f"    ⚠ Hidden: {', '.join(target['hidden_fields'])}")
    print()


def print_vuln_summary(all_vulns):
    print(f"\n{'='*70}")
    print("SCAN COMPLETE")
    print(f"{'='*70}\n")

    if not all_vulns:
        print("[✓] No SQL injection vulnerabilities detected\n")
        print(f"{'='*70}\n")
        return

    print(f"[!!!] TOTAL VULNERABILITIES FOUND: {len(all_vulns)}\n")
    print(f"{'='*70}")
    print("VULNERABILITY DETAILS")
    print(f"{'='*70}\n")

    for i, vuln in enumerate(all_vulns, 1):
        print(f" [{i}] {vuln['type']}  (source: {vuln.get('source', 'unknown')})")
        print(f"     Param:      {vuln.get('param', '?')}")
        print(f"     Payload:    {vuln['payload']}")
        if 'database' in vuln:
            print(f"     Database:   {vuln['database']}")
        if 'delay' in vuln:
            print(f"     Delay:      {vuln['delay']}")
        if 'true_similarity' in vuln:
            print(f"     TRUE sim:   {vuln['true_similarity']}")
            print(f"     FALSE sim:  {vuln['false_similarity']}")
        if 'columns' in vuln:
            print(f"     Columns:    {vuln['columns']}")
            if 'markers_found' in vuln:
                print(f"     Markers:    {', '.join(vuln['markers_found'])}")
        print()

    print(f"{'='*70}\n")


def scan(url):
    print_banner()
    print(f"\n[*] Target: {url}")
    print(f"[*] Starting scan...\n")

    targets = extract_targets(url)

    if not targets:
        print("[!] No forms or GET parameters found. Nothing to test.")
        return

    print(f"[+] Found {len(targets)} target(s) to test")

    all_vulns = []

    for i, target in enumerate(targets, 1):
        print_target_header(target, i, len(targets))

        vulns = run_all_detectors(target['url'], target['data'], target['method'])

        for v in vulns:
            v['source'] = target['source']

        if vulns:
            all_vulns.extend(vulns)
            print(f"\n    {'─'*66}")
            print(f"    [!!!] {target['source']} IS VULNERABLE — {len(vulns)} type(s) found")
            print(f"    {'─'*66}")
        else:
            print(f"\n    {'─'*66}")
            print(f"    [✓] {target['source']} appears SECURE")
            print(f"    {'─'*66}")

        time.sleep(1)

    print_vuln_summary(all_vulns)


if __name__ == "__main__":
    print("Only test sites you have permission to test!\n")

    target = input("Enter URL to scan: ").strip()

    if not target:
        print("\n[!] No URL provided. Using test example...")
        target = "http://testphp.vulnweb.com/login.php"
        print(f"[*] Testing: {target}")

    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    scan(target) 