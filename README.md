# Bypasser

**Modular WAF/IPS evasion framework for authorized security testing.**

`Python 3` · `Standard Library Only` · `Zero Dependencies` · `Kali Linux` · `WSL`

> Built for authorized penetration testing, security research, laboratories, and controlled environments.

---

## Overview

**Bypasser** is a lightweight framework for testing Web Application Firewalls (WAF) and Intrusion Prevention Systems (IPS).

It combines:

* Modular evasion plugins
* Payload-driven testing
* WAF fingerprinting
* Multi-signal validation
* Confidence scoring from `0–100`
* Structured JSON reporting
* Audit logging

The framework is designed to remain lightweight and requires no third-party Python packages.

---

## Installation

Clone the repository and run the environment check:

```bash
git clone https://github.com/<your-username>/bypasser.git
cd bypasser

python3 run.py --check
```

No virtual environment, `pip`, or external Python dependencies are required.

---

## Usage

### Syntax

```bash
python3 run.py scan \
  --url <URL> \
  --param <PARAMETER> \
  --type <TYPE> \
  [options]
```

### Examples

SQL Injection:

```bash
python3 run.py scan \
  --url "http://target/login.php" \
  --param user \
  --type sqli \
  --method POST \
  --data "pass=123" \
  --verify "Welcome"
```

XSS:

```bash
python3 run.py scan \
  --url "http://target/search.php" \
  --param q \
  --type xss \
  --method GET
```

Traversal through a proxy:

```bash
python3 run.py scan \
  --url "http://target/index.php" \
  --param page \
  --type traversal \
  --proxy http://127.0.0.1:8080 \
  --workers 4
```

RCE without stopping after the first result:

```bash
python3 run.py scan \
  --url "http://target/cgi-bin/exec" \
  --param cmd \
  --type rce \
  --no-stop \
  --threshold 60
```

---

## Payload Types

| Type        | Description                    |
| ----------- | ------------------------------ |
| `sqli`      | SQL Injection                  |
| `xss`       | Reflected and DOM XSS          |
| `traversal` | Path Traversal / LFI           |
| `rce`       | Command Injection              |
| `ssti`      | Server-Side Template Injection |
| `ssrf`      | Server-Side Request Forgery    |

---

## Main Options

| Option             | Description                     |
| ------------------ | ------------------------------- |
| `--url URL`        | Target URL                      |
| `--param NAME`     | Injection parameter             |
| `--type TYPE`      | Payload category                |
| `--method METHOD`  | `GET` or `POST`                 |
| `--data DATA`      | Additional request data         |
| `--header "K: V"`  | Additional HTTP header          |
| `--cookie "K=V"`   | Session cookie                  |
| `--verify TEXT`    | Expected reflection marker      |
| `--max-payloads N` | Maximum payloads                |
| `--max-chains N`   | Maximum evasion chains          |
| `--workers N`      | Parallel workers                |
| `--proxy URL`      | HTTP proxy                      |
| `--delay S`        | Delay between probes            |
| `--jitter S`       | Random delay variation          |
| `--timeout S`      | Request timeout                 |
| `--threshold N`    | Minimum bypass confidence       |
| `--no-stop`        | Continue after the first bypass |
| `--list-evasions`  | List available evasions         |
| `--outdir DIR`     | Report directory                |

Full command help:

```bash
python3 run.py scan --help
```

---

## Evasion Engine

Bypasser uses modular evasion plugins that can be combined into payload chains.

Included techniques include:

```text
url
double_url
hex
unicode
html_entities
base64
case
sql_comments
whitespace
null_byte
overlong
hpp
chunked
json
xml
```

Each technique is implemented independently, allowing the framework to be extended without changing the core scanning engine.

---

## Validation

Results are evaluated using multiple signals instead of HTTP status alone.

Signals may include:

```text
HTTP status
Reflection
Database errors
Response differences
Timing anomalies
Baseline deviations
Behavioral anomalies
```

Every probe receives a verdict:

```text
bypass
blocked
anomaly
clean
error
```

and a confidence score from `0–100`.

---

## WAF Detection

WAF fingerprinting compares headers, cookies, status codes, and response bodies against configurable signatures.

Signature database:

```text
configs/waf_signatures.yaml
```

Supported signatures include major platforms such as:

```text
Cloudflare
AWS WAF
Akamai
F5 BIG-IP ASM
Imperva
ModSecurity / OWASP CRS
FortiWeb
Sucuri
Wordfence
Barracuda
```

Additional signatures can be added through the configuration system.

---

## Output

Console results provide:

```text
Verdict
Confidence
HTTP status
Response time
Detected signals
Payload
Evasion chain
```

Structured reports:

```text
reports/scan_<timestamp>.json
```

Audit log:

```text
logs/events.jsonl
```

Reports contain payload information, evasion chains, signals, WAF detection, confidence, and final verdict.

---

## Configuration

Global settings are stored in:

```text
configs/settings.yaml
```

Configuration controls:

```text
Enabled evasions
Proxies
Workers
Delays
Thresholds
Block codes
Execution limits
Output paths
```

---

## Architecture

```text
bypasser/
├── run.py
├── wafkit/
│   ├── core/
│   ├── evasions/
│   ├── payloads/
│   └── utils/
├── configs/
├── reports/
└── logs/
```

Core responsibilities:

```text
core/       → session, baseline, fingerprinting, validation
evasions/   → evasion plugins
payloads/   → payload loading
utils/      → logging and utilities
configs/    → settings and WAF signatures
```

---

## Responsible Use

Bypasser is intended only for authorized security testing.

Use it exclusively against systems that you own or are explicitly authorized to assess, including:

* Penetration testing
* Security laboratories
* Internal assessments
* CTF environments
* Defensive WAF/IPS validation

Unauthorized testing may be illegal.

**The operator is responsible for keeping all activity within the authorized scope.**

---

## Contributing

Contributions are welcome in architecture, testing, documentation, validation, and new compatible modules.

Before submitting changes:

```bash
python3 run.py --check
```

Test all changes in a controlled environment.

---

## License

Distributed under the **MIT License**.

See `LICENSE` for the full terms.

---

## Disclaimer

Bypasser is provided for educational purposes, security research, and authorized security assessments.

The authors and contributors are not responsible for misuse, damage, service disruption, or legal consequences resulting from use of the software.

**Use only against authorized targets.**
