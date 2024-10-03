# SQLiGuard

**SQLiGuard** is a Python-based scanner that detects SQL injection vulnerabilities in a URL with commonly used payloads.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

## Installation

### Prerequisites

Ensure you have Python 3.7 installed and install the following dependencies:
- `requests`
- `argparse`

To install the required dependencies, run:
  ```bash
  pip install requests argparse
  ```

### Project Setup

1. Clone the repository to your local machine:
  ```bash
  git clone https://github.com/HackGuard/SQLiGuard.git
  ```

2. Navigate to the project directory:
  ```bash
  cd SQLiGuard
  ```

## Usage

To run the scanner, use the following command:
  ```bash
  python main.py -u <target_url>
  ```
Replace `<target_url>` with the website URL you want to scan for SQL vulnerabilities.

**Example:**
  ```bash
  python main.py -u "http://example.com/page?id=1"
  ```

### Arguments
`-u, --url`: The target URL to scan for SQL vulnerabilities.

## Examples
Example output:
 ```bash
  ____   ___  _     _  ____                     _
 / ___| / _ \| |   (_)/ ___|_   _  __ _ _ __ __| |
 \___ \| | | | |   | | |  _| | | |/ _` | '__/ _` |
  ___) | |_| | |___| | |_| | |_| | (_| | | | (_| |
 |____/ \__\_\_____|_|\____|\__,_|\__,_|_|  \__,_|v1.0
 
[!] Scanning. Payload: ' OR 1=1 --
[*] Vulnerability Found: http://example.com/page?id=1' OR 1=1 --
Do you want to continue scanning? (y/n):
```

## Contributing
We welcome contributions! To learn more about how to contribute to this project, please refer to our [CONTRIBUTING.md](CONTRIBUTING.md) file.

## Disclaimer
Using this tool on websites without proper authorization could be considered **unauthorized access** or **hacking**. It is unethical and potentially illegal to use SQLiGuard on websites that you do not own or have explicit permission to test.

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
