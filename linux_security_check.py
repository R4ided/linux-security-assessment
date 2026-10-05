```python
#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
import time

# -----------------------------
# Terminal colors
# -----------------------------

RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
WHITE = "\033[97m"


results = []


def clear_screen():
    os.system("clear")


def banner():
    print(CYAN + BOLD)
    print("╔══════════════════════════════════════════════════════╗")
    print("║            LINUX SECURITY ASSESSMENT                ║")
    print("║                  Security Audit                     ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(RESET)


def section(title):
    print()
    print(BLUE + BOLD + f"── {title} " + "─" * (48 - len(title)) + RESET)


def status_line(status, name):
    if status == "PASS":
        print(f"  {GREEN}✔ PASS{RESET}   {name}")
    elif status == "WARN":
        print(f"  {YELLOW}⚠ WARN{RESET}   {name}")
    elif status == "FAIL":
        print(f"  {RED}✖ FAIL{RESET}   {name}")


def add_result(name, status, message=""):
    results.append((name, status))
    status_line(status, name)

    if message:
        print(f"           {message}")


def run_command(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        return None
    except Exception:
        return None


# -----------------------------
# Security checks
# -----------------------------

def check_updates():
    section("SYSTEM UPDATES")

    if shutil.which("apt"):
        result = run_command(["apt", "list", "--upgradable"])

        if result and result.returncode == 0:
            lines = [
                line for line in result.stdout.splitlines()
                if "/" in line and "Listing..." not in line
            ]

            if lines:
                add_result(
                    "System updates",
                    "WARN",
                    f"{len(lines)} package(s) may need updates."
                )
            else:
                add_result("System updates", "PASS")

        else:
            add_result(
                "System updates",
                "WARN",
                "Could not check for available updates."
            )

    else:
        add_result(
            "System updates",
            "WARN",
            "APT package manager was not found."
        )


def check_firewall():
    section("FIREWALL")

    if shutil.which("ufw"):
        result = run_command(["ufw", "status"])

        if result and "Status: active" in result.stdout:
            add_result("Firewall status", "PASS", "UFW is active.")

        else:
            add_result(
                "Firewall status",
                "WARN",
                "UFW does not appear to be active."
            )

    elif shutil.which("firewall-cmd"):
        result = run_command(["firewall-cmd", "--state"])

        if result and result.stdout.strip() == "running":
            add_result("Firewall status", "PASS", "firewalld is running.")

        else:
            add_result(
                "Firewall status",
                "WARN",
                "firewalld does not appear to be running."
            )

    else:
        add_result(
            "Firewall status",
            "WARN",
            "No supported firewall command was found."
        )


def check_ports():
    section("NETWORK")

    result = run_command(["ss", "-lntu"])

    if result and result.returncode == 0:
        lines = result.stdout.strip().splitlines()

        # Remove header
        ports = lines[1:] if len(lines) > 1 else []

        add_result(
            "Listening ports",
            "PASS",
            f"{len(ports)} listening endpoint(s) detected."
        )

        print()
        print(CYAN + "  Listening endpoints:" + RESET)

        for line in ports:
            print("   ", line)

    else:
        add_result(
            "Listening ports",
            "WARN",
            "Could not inspect listening ports."
        )


def check_ssh():
    section("SSH CONFIGURATION")

    path = "/etc/ssh/sshd_config"

    if not os.path.exists(path):
        add_result(
            "SSH configuration",
            "PASS",
            "SSH server configuration was not found."
        )
        return

    result = run_command([
        "grep",
        "-Ei",
        r"^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)"
        ,
        path
    ])

    if result and result.returncode == 0:
        add_result(
            "SSH configuration",
            "PASS",
            "SSH configuration directives were found."
        )

        print()
        for line in result.stdout.splitlines():
            print("      " + line)

    else:
        add_result(
            "SSH configuration",
            "WARN",
            "Could not inspect SSH configuration."
        )


def check_root():
    section("ROOT ACCOUNT")

    if not shutil.which("passwd"):
        add_result(
            "Root login",
            "WARN",
            "passwd command was not found."
        )
        return

    result = run_command(["passwd", "-S", "root"])

    if result and result.returncode == 0:
        output = result.stdout.strip()

        if " L " in output:
            add_result(
                "Root login",
                "PASS",
                "Root account appears locked."
            )
        else:
            add_result(
                "Root login",
                "WARN",
                "Root account may be enabled."
            )

    else:
        add_result(
            "Root login",
            "WARN",
            "Could not determine root account status."
        )


def check_users():
    section("USER ACCOUNTS")

    command = [
        "sh",
        "-c",
        "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
    ]

    result = run_command(command)

    if result and result.returncode == 0:
        users = [
            user.strip()
            for user in result.stdout.splitlines()
            if user.strip()
        ]

        add_result(
            "User accounts",
            "PASS",
            f"{len(users)} regular user account(s) detected."
        )

        if users:
            print()
            for user in users:
                print(f"      • {user}")

    else:
        add_result(
            "User accounts",
            "WARN",
            "Could not inspect local user accounts."
        )


def check_sudo():
    section("PRIVILEGE ACCESS")

    if not shutil.which("sudo"):
        add_result(
            "Sudo access",
            "WARN",
            "sudo command was not found."
        )
        return

    result = run_command(["sudo", "-n", "true"])

    if result and result.returncode == 0:
        add_result(
            "Sudo access",
            "PASS",
            "Current user has non-interactive sudo access."
        )
    else:
        add_result(
            "Sudo access",
            "WARN",
            "Sudo may require authentication or may be unavailable."
        )


def check_permissions():
    section("FILE PERMISSIONS")

    try:
        mode = os.stat("/etc/shadow").st_mode & 0o777

        if mode & 0o007:
            add_result(
                "Shadow file permissions",
                "FAIL",
                "/etc/shadow is accessible by other users."
            )
        else:
            add_result(
                "Shadow file permissions",
                "PASS",
                "No permissions for 'others' detected."
            )

    except OSError:
        add_result(
            "Shadow file permissions",
            "WARN",
            "Could not inspect /etc/shadow."
        )


def check_services():
    section("SYSTEM SERVICES")

    if not shutil.which("systemctl"):
        add_result(
            "Enabled services",
            "WARN",
            "systemctl was not found."
        )
        return

    result = run_command([
        "systemctl",
        "list-unit-files",
        "--state=enabled",
        "--type=service",
        "--no-pager"
    ])

    if result and result.returncode == 0:
        services = [
            line for line in result.stdout.splitlines()
            if ".service" in line
        ]

        add_result(
            "Enabled services",
            "PASS",
            f"{len(services)} enabled service(s) detected."
        )

    else:
        add_result(
            "Enabled services",
            "WARN",
            "Could not list enabled services."
        )


def check_logs():
    section("SECURITY LOGS")

    if not shutil.which("journalctl"):
        add_result(
            "Security logs",
            "WARN",
            "journalctl was not found."
        )
        return

    result = run_command([
        "journalctl",
        "-n",
        "5",
        "--no-pager"
    ])

    if result and result.returncode == 0:
        add_result(
            "Security logs",
            "PASS",
            "Recent system logs are accessible."
        )

        print()
        print(CYAN + "  Recent log entries:" + RESET)

        for line in result.stdout.splitlines():
            print("      " + line)

    else:
        add_result(
            "Security logs",
            "WARN",
            "Could not read recent system logs."
        )


# -----------------------------
# Summary
# -----------------------------

def final_summary():
    section("FINAL SECURITY SUMMARY")

    passed = sum(status == "PASS" for _, status in results)
    warnings = sum(status == "WARN" for _, status in results)
    failed = sum(status == "FAIL" for _, status in results)

    total = len(results)

    if failed:
        score = max(0, int((passed / total) * 100))
        rating = RED + "CRITICAL" + RESET

    elif warnings:
        score = int((passed / total) * 100)
        rating = YELLOW + "NEEDS REVIEW" + RESET

    else:
        score = 100
        rating = GREEN + "GOOD" + RESET

    print()
    print("  ┌──────────────────────────────────────┐")
    print(f"  │ Security Score: {score:>3}%               │")
    print("  ├──────────────────────────────────────┤")
    print(f"  │ {GREEN}PASS{RESET}: {passed:<3}                           │")
    print(f"  │ {YELLOW}WARN{RESET}: {warnings:<3}                           │")
    print(f"  │ {RED}FAIL{RESET}: {failed:<3}                           │")
    print("  ├──────────────────────────────────────┤")
    print(f"  │ Rating: {rating:<26} │")
    print("  └──────────────────────────────────────┘")

    print()
    print("  " + CYAN + "Assessment complete." + RESET)
    print()


# -----------------------------
# Main
# -----------------------------

def main():
    clear_screen()
    banner()

    print("  Starting security assessment...")
    print()

    time.sleep(0.5)

    check_updates()
    check_firewall()
    check_ports()
    check_ssh()
    check_root()
    check_users()
    check_sudo()
    check_permissions()
    check_services()
    check_logs()

    final_summary()


if __name__ == "__main__":
    main()
```










