import requests
import argparse
from payloads import load_payloads
import urllib3
from requests_futures.sessions import FuturesSession

RED = '\033[91m'
GREEN = '\033[92m'
ORANGE = '\033[38;5;208m'
YELLOW = '\033[93m'
CYAN = '\033[36m'
PURPLE = '\033[95m'
RESET = '\033[0m'

payloads = load_payloads('payloads.txt')

syntaxErrors = [
    "SQL syntax"
]

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        self.foundError = []

    def display_banner(self):
        print(f"""
      ____   ___  _     _  ____                     _ 
     / ___| / _ \| |   (_)/ ___|_   _  __ _ _ __ __| |
     \___ \| | | | |   | | |  _| | | |/ _` | '__/ _` |
      ___) | |_| | |___| | |_| | |_| | (_| | | | (_| |
     |____/ \__\_\_____|_|\____|\__,_|\__,_|_|  \__,_|{GREEN}v1.1{RESET} 
                                                          
    """)

class DirectoryScanner(VulnerabilityScanner):
    def __init__(self, url):
        super().__init__(url)
    
    def scan_directories(self):
        filePath = "wordlist.txt"
        with open(filePath, "r") as file:
            directories = [line.strip() for line in file]

        print(f"{ORANGE}[!] Directory Scanning Started\n{RESET}")
        foundURL = 0 

        for dr in directories:
            test_url = f"{self.url}/{dr}"
            try:
                response = requests.get(test_url, allow_redirects=True, timeout=5)
                if response.status_code == 200:
                    self.foundError.append(test_url)
                    foundURL += 1
                    
            except requests.exceptions.RequestException:
                print(f"Error accessing {test_url}")
                exit(1)

            except urllib3.exceptions.InsecureRequestWarning:
                print("Error")
                exit(1)

        if foundURL >= 1:
            print(f"{RED}[*] It found {foundURL} different directories.\n{RESET}")
            return True
        else:
            print(f"{RED}[*] No URL Found\n{RESET}")
            return False

class SqlInjectionScanner(VulnerabilityScanner):
    def __init__(self, url):
        super().__init__(url)

    def scan_sql_injection(self):
        if '?' not in self.url:
            self.url = self.url.rstrip('/') + '/'

        vulnerabilities_found = 0
        session = FuturesSession() 
        futures = []
        vulnerablePayload = None

        for payload in payloads:
            testUrl = f"{self.url}{payload}"
            futures.append(session.get(testUrl))

        for future in futures:
            try:
                response = future.result()
                if any(error in response.text for error in syntaxErrors):
                    vulnerabilities_found += 1
                    if vulnerablePayload is None:
                        vulnerablePayload = payload

            except requests.exceptions.RequestException as e:
                print(f"{RED}Error: {RESET}{e}")

        if vulnerabilities_found == 0:
            print(f"{RED}[*] No Vulnerability found.{RESET}")
        else:
            print(f"{GREEN}[*] Vulnerabilities Found: {RESET}{self.url}")
            if vulnerablePayload:
                print(f"{YELLOW}[*] Vulnerable Payload: {RESET}{vulnerablePayload}")

        return vulnerabilities_found > 0

class DeepScan(DirectoryScanner, SqlInjectionScanner):
    def __init__(self, url):
        super().__init__(url)

    def deepscan(self):
        if self.scan_directories():
            for error_url in self.foundError:
                print(f"{CYAN}\n[*] Scanning for SQL injection vulnerabilities on: {RESET}{error_url}")
                sql_scanner = SqlInjectionScanner(error_url)
                sql_scanner.scan_sql_injection()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Scanner and Directory Finder")

    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("--deep-scan", action="store_true", help="Perform both directory and SQL injection scan")
    parser.add_argument("--sql-scan", action="store_true", help="Scan for SQL injection vulnerabilities")
    args = parser.parse_args()

    scanner = VulnerabilityScanner(args.url)
    scanner.display_banner()

    if args.deep_scan:
        deepScan = DeepScan(args.url)
        deepScan.deepscan()

    elif args.sql_scan:
        sql_scanner = SqlInjectionScanner(args.url)
        sql_scanner.scan_sql_injection()

    else:
        print(f"{RED}[!] Please enter a valid parameter.{RESET}")