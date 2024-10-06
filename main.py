import requests
import argparse
from payloads import load_payloads
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI color codes for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
ORANGE = '\033[38;5;208m'
YELLOW = '\033[93m'
CYAN = '\033[36m'
PURPLE = '\033[95m'
RESET = '\033[0m'

# Load SQL injection payloads from the file
payloads = load_payloads('payloads.txt')

# Common SQL syntax errors to detect vulnerabilities
syntaxErrors = [
    "SQL syntax"
]

foundError = []

def DirectoryFinder(url):
    url = url if url.startswith(('http://', 'https://')) else 'http://' + url
    filePath = "wordlist.txt"
    with open(filePath, "r") as file:
        directories = [line.strip() for line in file]

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_directory, url, dr): dr for dr in directories}

        for future in as_completed(futures):
            dr = futures[future]
            try:
                future.result()  # This will raise any exceptions from the thread
            except Exception as e:
                print(f"Error accessing {url}/{dr}: {e}")

def check_directory(url, directory):
    test_url = f"{url}/{directory}"
    response = requests.get(test_url, allow_redirects=True, timeout=5)
    if response.status_code == 200:
        print(f"Found: {test_url}")
        foundError.append(test_url)
    else:
        print(f"Not found: {test_url}")

def display_banner():
    print(f"""
  ____   ___  _     _  ____                     _ 
 / ___| / _ \| |   (_)/ ___|_   _  __ _ _ __ __| |
 \___ \| | | | |   | | |  _| | | |/ _` | '__/ _` |
  ___) | |_| | |___| | |_| | |_| | (_| | | | (_| |
 |____/ \__\_\_____|_|\____|\__,_|\__,_|_|  \__,_|{GREEN}v1.0{RESET} 
                                                  
""")

def SqlInjectionScanner(url):
    # Normalize URL: add 'http://' if missing and ensure it ends with a '/'
    url = url if url.startswith(('http://', 'https://')) else 'http://' + url
    url = url.rstrip('/') + '/' if '?' not in url else url

    vulnerabilities_found = 0  # Initialize a counter for vulnerabilities

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_sql_injection, url, payload): payload for payload in payloads}

        for future in as_completed(futures):
            payload = futures[future]
            try:
                if future.result():  # Check if a vulnerability was found
                    vulnerabilities_found += 1
            except Exception as e:
                print(f"{RED}Error during scan with payload {payload}: {RESET}{e}")

    if vulnerabilities_found == 0:
        print(f"{RED}[*] No Vulnerability found.{RESET}")
    else:
        print(f"{GREEN}[*] Total Vulnerabilities Found: {vulnerabilities_found}{RESET}")

    return vulnerabilities_found > 0  # Return True if any vulnerabilities found, otherwise False

def check_sql_injection(url, payload):
    testUrl = f"{url}{payload}"
    response = requests.get(testUrl)

    if any(error in response.text for error in syntaxErrors):
        print(f"{GREEN}[*] Vulnerability Found: {RESET}{CYAN}{testUrl}{RESET}")
        user_choice = input(f"{YELLOW}Do you want to continue scanning? (y/n): {RESET}")
        if user_choice.lower() != 'y':
            print(f"{PURPLE}[*] Stopping scan on user request.{RESET}")
            return True  # Indicate a vulnerability was found and user wants to stop
    print(f"{ORANGE}[!] Scanning. Payload: {RESET}{YELLOW}{payload}{RESET}")
    return False  # Indicate no vulnerability was found

if __name__ == "__main__":
    # Argument parser for command-line options
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan for SQL vulnerabilities")

    # Parse command-line arguments
    args = parser.parse_args()

    display_banner()
    SqlInjectionScanner(args.url)
