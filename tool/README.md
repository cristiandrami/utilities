# Cry Pipeline

Cry Pipeline is a tool for subdomain analysis and IP address scanning. It allows you to gather information about the subdomains of a specified domain and perform an Nmap scan on them to identify the running services.

## Prerequisites

- Python 3.x
- Dependencies listed in the `requirements.txt` file

## Installation

1. Clone the repository:
```
git clone https://github.com/cristiandrami/utilities
```

2. Navigate to the project directory:
```
cd utilities/tool
```

3. Install the dependencies:
```
pip install -r requirements.txt
```

4. Install needed commands
    1. `./install_linx.sh` for Linux based systems
    2. `./install_macOS.sh` for macOS based systems

## Usage

```sh
python3 crypipe.py [OPTIONS] --domain DOMAIN
```

### Arguments:
- `--domain, -d TEXT`: Domain to scan (REQUIRED)

### Options:
- `--all-subdomains, -a`: Process all subdomains (default: False)
- `--report, -r`: Create the report (default: False) (Execute first the scan and then the report generation. If combined with `-a` it will create a report also for subdomains)


## Key Features
- Subdomain analysis using Sublist3r
- Scanning of IP addresses corresponding to subdomains using Nmap
- Web service scanning using tools such as Dirb, Nuclei, Joomla, and Nikto
- Generation of reports on scan results



## Examples
1. Scan a single domain:

```sh
python3 crypipe.py --domain example.com
```

2. Scan all subdomains of a domain:

```sh
python3 crypipe.py --domain example.com --all-subdomains
```

3. Create a report (main domain only)
```sh
python3 crypipe.py --domain example.com --report
```

4. Create a report (main domain and subdomains)
```sh
python3 crypipe.py --domain example.com -a --report
```
