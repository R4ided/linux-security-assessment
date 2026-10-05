#!/usr/bin/env python3

import os
import shutil
import subprocess
import time

results = []

# Colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BLUE = "\033[94m"


def clear_screen():
    os.system("clear")


def banner():
    print(CYAN + BOLD)
    print("╔══════════════════════════════════════════════╗")
    print("║        LINUX SECURITY ASSESSMENT            ║")
    print("║              SECURITY AUDIT                  ║")
    print("╚══════════════════════════════════════════════╝")
    print(RESET)


def section(title):
    print()
    print(BLUE + BOLD + f"── {title} ──────────────────────────────" + RESET)


def add_result(name, status, message=""):
    results.append((name, status))

    if status == "PASS":
        symbol = GREEN + "✔ PASS" + RESET
    elif status == "WARN":
        symbol = YELLOW + "⚠ WARN" + RESET
    else:
        symbol = RED + "✖ FAIL" + RESET

    print(f"  {symbol}   {name}")

    if message:
        print(f"           {message}")


def run_command(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True
        )
    except Exception:
        return None


def check_updates():
    section("SYSTEM UPDATES")

    if shutil.which("apt"):
        result = run_command(["apt", "list", "--upgradable"])

        if result and result.returncode == 0:
            packages = [
                line for line in result.stdout.splitlines()
                if "/" in line and "Listing" not in line
            ]

            if packages:
                add_result(
                    "System updates",
                    "WARN",
                    f"{len(packages)} update(s) available."
                )
            else:
                add_result("System updates", "PASS")

        else:
            add_result(
                "System updates",
                "WARN",
                "Could not check for updates."
            )
    else:
        add_result(
            "System updates",
            "WARN",
            "APT was not found."
        )


def check_firewall():
    section("FIREWALL")

    if shutil.which("ufw"):
        result = run_command(["ufw", "status"])

        if result and "Status: active" in result.stdout:
            add_result(
                "Firewall",
                "PASS",
                "UFW firewall is active."
            )
        else:
            add_result(
                "Firewall",
                "WARN",
                "UFW is not active."
            )

    elif shutil.which("firewall-cmd"):
        result = run_command(["firewall-cmd", "--state"])

        if result and result.stdout.strip() == "running":
            add_result(
                "Firewall",
                "PASS",
                "firewalld is running."
            )
        else:
            add_result(
                "Firewall",
                "WARN",
                "firewalld is not running."
            )

    else:
        add_result(
            "Firewall",
            "WARN",
            "No supported firewall was found."
        )


def check_ports():
    section("LISTENING PORTS")

    result = run_command(["ss", "-lntu"])

    if result and result.returncode == 0:
        lines = result.stdout.strip().splitlines()
        ports = lines[1:] if len(lines) > 1 else []

        add_result(
            "Listening ports",
            "PASS",
            f"{len(ports)} listening endpoint(s) found."
        )

        if ports:
            print()
            print(CYAN + "  Listening endpoints:" + RESET)

            for port in ports:
                print("    " + port)
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
        r"^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)",
        path
    ])

    if result and result.returncode == 0:
        add_result(
            "SSH configuration",
            "PASS",
            "SSH configuration directives found."
        )

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
            "Root account",
            "WARN",
            "passwd command was not found."
        )
        return

    result = run_command(["passwd", "-S", "root"])

    if result and result.returncode == 0:
        output = result.stdout.strip()

        if " L " in output:
            add_result(
                "Root account",
                "PASS",
                "Root account appears to be locked."
            )
        else:
            add_result(
                "Root account",
                "WARN",
                "Root account may be enabled."
            )
    else:
        add_result(
            "Root account",
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
            f"{len(users)} regular user account(s) found."
        )

        for user in users:
            print(f"      • {user}")
    else:
        add_result(
            "User accounts",
            "WARN",
            "Could not inspect user accounts."
        )


def check_sudo():
    section("SUDO ACCESS")

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
            "Current user has sudo access."
        )
    else:
        add_result(
            "Sudo access",
            "WARN",
            "Sudo requires authentication or is unavailable."
        )


def check_permissions():
    section("FILE PERMISSIONS")

    try:
        mode = os.stat("/etc/shadow").st_mode & 0o777

        if mode & 0o007:
            add_result(
                "Shadow permissions",
                "FAIL",
                "/etc/shadow is accessible by other users."
            )
        else:
            add_result(
                "Shadow permissions",
                "PASS",
                "/etc/shadow is not accessible by others."
            )

    except OSError:
        add_result(
            "Shadow permissions",
            "WARN",
            "Could not inspect /etc/shadow."
        )


def check_services():
    section("ENABLED SERVICES")

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
            f"{len(services)} enabled service(s) found."
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
        for line in result.stdout.splitlines():
            print("      " + line)
    else:
        add_result(
            "Security logs",
            "WARN",
            "Could not read system logs."
        )


def final_summary():
    section("FINAL SUMMARY")

    passed = sum(status == "PASS" for _, status in results)
    warnings = sum(status == "WARN" for _, status in results)
    failed = sum(status == "FAIL" for _, status in results)

    total = len(results)

    if total > 0:
        score = int((passed / total) * 100)
    else:
        score = 0

    if failed:
        rating = RED + "CRITICAL" + RESET
    elif warnings:
        rating = YELLOW + "NEEDS REVIEW" + RESET
    else:
        rating = GREEN + "GOOD" + RESET

    print()
    print("  ╔══════════════════════════════════════╗")
    print(f"  ║ Security Score: {score:>3}%              ║")
    print("  ╠══════════════════════════════════════╣")
    print(f"  ║ PASS: {passed:<3}                           ║")
    print(f"  ║ WARN: {warnings:<3}                           ║")
    print(f"  ║ FAIL: {failed:<3}                           ║")
    print("  ╠══════════════════════════════════════╣")
    print(f"  ║ Rating: {rating:<24} ║")
    print("  ╚══════════════════════════════════════╝")
    print()
    print(CYAN + "  Assessment complete." + RESET)
    print()


def main():
    clear_screen()
    banner()

    print("  Starting security assessment...")
    time.sleep(1)

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
