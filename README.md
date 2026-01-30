# Livewire Passive Vulnerability Scanner

Livewire Passive Vulnerability Scanner is a Python 2.7 tool designed to **passively detect Livewire versions** used by websites and identify potential vulnerabilities based on version comparison.

This scanner **does not exploit** any vulnerability. It only analyzes publicly accessible page content (HTML/JavaScript) to determine the detected Livewire version.

---

## Features

- Passive vulnerability detection (non-intrusive)
- Multi-threaded scanning for improved performance
- Real-time saving of vulnerable results
- Automatic URL normalization (http / https)
- Simple and clean output (domain-based)
- Python 2.7 compatible

---

## Detection Logic

A target is considered **VULNERABLE** if:

```

Livewire version < 3.6.4

````

Versions equal to or higher than `3.6.4` are marked as **SAFE**.

---

## Requirements

- Python 2.7
- Required library:
  - `requests`

Install dependencies:
```bash
pip install requests
````

---

## Usage

1. Prepare a target list file (e.g. `list.txt`):

   ```
   example.com
   https://targetsite.com
   sub.domain.com
   ```

2. Run the scanner:

   ```bash
   python livewire_scan.py list.txt
   ```

3. Vulnerable targets will be saved to:

   ```
   vuln.txt
   ```

---

## Output Example

Terminal output:

```
[+] VULN  : example.com | Livewire 3.5.2
[-] SAFE  : targetsite.com | Livewire 3.6.4
[!] ERROR : timeoutsite.com
```

Saved file (`vuln.txt`):

```
example.com
another-vulnerable-site.com
```

---

## Disclaimer

This tool is provided **for educational and authorized security testing purposes only**.

* Use this tool only on systems you own or have explicit permission to test
* The author assumes **no responsibility** for misuse or illegal activities
* 
More Disclaimer You Can see the disclaimer on the cover of Jenderal92. You can check it [HERE !!!](https://github.com/Jenderal92/)
