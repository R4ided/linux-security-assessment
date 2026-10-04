
# Linux Security Assessment

## Purpose
This project is a Python-based tool that performs 10 basic security
checks on a Linux system. It reports PASS, WARN, or FAIL and provides
a summary of the results.

## Security Checks
1. System updates
2. Firewall status
3. Listening ports
4. SSH configuration
5. Root-level accounts
6. User accounts
7. Sudo access
8. File permissions
9. Enabled services
10. Security logs

## Requirements
- Linux or WSL environment
- Python 3
- Git
- Appropriate Linux utilities for the checks

Some checks may require administrator privileges or services that
are not available in every environment.

## Usage
Run the script with:

    python3 linux_security_check.py

Check Python syntax with:

    python3 -m py_compile linux_security_check.py

## Example Output
    LINUX SECURITY ASSESSMENT
    [PASS] System updates
    [WARN] Firewall status
           Reason: No supported firewall tool found.

    FINAL SUMMARY
    PASS: 8
    WARN: 2
    FAIL: 0
    TOTAL: 10

This is an example based on one test run. Actual results vary by system.

## Disclaimer
This tool is for educational and defensive purposes only. It performs
basic checks and does not guarantee system security or automatically
fix vulnerabilities. Review warnings and results manually. Only test
systems you own or have permission to assess.
