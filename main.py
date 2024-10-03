import requests
import argparse
from payloads import load_payloads
import urllib3

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

    for dr in directories:
        test_url = f"{url}/{dr}"
        try:
            response = requests.get(test_url, allow_redirects=True, timeout=5)
            if response.status_code == 200:
                print(f"Found: {test_url}")
                foundError.append(test_url)
                print(foundError)

            else:
                print(f"Not found: {test_url}")

        except requests.exceptions.RequestException as e:
            print(f"Error accessing {test_url}")
            exit(1)

        except urllib3.exceptions.InsecureRequestWarning:
            print("error")
            exit(1)

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

    for payload in payloads:
        testUrl = f"{url}{payload}"
        try:
            response = requests.get(testUrl)
            if any(error in response.text for error in syntaxErrors):
                print(f"{GREEN}[*] Vulnerability Found: {RESET}{CYAN}{testUrl}{RESET}")
                vulnerabilities_found += 1  # Increment the count when a vulnerability is found
                
                # Ask if the user wants to continue scanning after finding a vulnerability
                user_choice = input(f"{YELLOW}Do you want to continue scanning? (y/n): {RESET}")
                if user_choice.lower() != 'y':
                    print(f"{PURPLE}[*] Stopping scan on user request.{RESET}")
                    break  # Stop scanning if the user chooses not to continue

            print(f"{ORANGE}[!] Scanning. Payload: {RESET}{YELLOW}{payload}{RESET}")

        except requests.exceptions.RequestException as e:
            print(f"{RED}Error: {RESET}{e}")
            exit(1)

    if vulnerabilities_found == 0:
        print(f"{RED}[*] No Vulnerability found.{RESET}")
    else:
        print(f"{GREEN}[*] Total Vulnerabilities Found: {vulnerabilities_found}{RESET}")

    return vulnerabilities_found > 0  # Return True if any vulnerabilities found, otherwise False

if __name__ == "__main__":
    # Argument parser for command-line options
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan for SQL vulnerabilities")

    # Parse command-line arguments
    args = parser.parse_args()

    display_banner()
    SqlInjectionScanner(args.url)