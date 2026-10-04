
#!/usr/bin/env python3

import os
import pwd
import shutil
import subprocess

results = []


def check(name, command, explanation=None):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            status = "PASS"
            message = "Check completed successfully."
        else:
            status = "WARN"
            message = explanation or "The check could not be completed."
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        status = "WARN"
        message = explanation or "Required command unavailable."

    results.append((name, status))
    print(f"[{status}] {name}")
    if status != "PASS":
        print(f"       Reason: {message}")


def main():
    print("LINUX SECURITY ASSESSMENT")
    print("=" * 32)

    # 1. System updates
    if shutil.which("apt"):
        check("System updates", ["apt", "list", "--upgradable"],
              "Could not check available updates.")
    elif shutil.which("dnf"):
        check("System updates", ["dnf", "check-update"],
              "Could not check available updates.")
    else:
        results.append(("System updates", "WARN"))
        print("[WARN] System updates")
        print("       Reason: Unsupported package manager.")

    # 2. Firewall status
    if shutil.which("ufw"):
        check("Firewall status", ["ufw", "status"])
    elif shutil.which("firewall-cmd"):
        check("Firewall status", ["firewall-cmd", "--state"])
    else:
        results.append(("Firewall status", "WARN"))
        print("[WARN] Firewall status")
        print("       Reason: No supported firewall tool found.")

    # 3. Listening ports
    check("Listening ports", ["ss", "-lntu"],
          "Could not inspect listening ports.")

    # 4. SSH configuration
    try:
        with open("/etc/ssh/sshd_config") as file:
            config = file.read().lower()
        if "permitrootlogin no" in config:
            status = "PASS"
            message = ""
        else:
            status = "WARN"
            message = "Root login setting needs review."
    except OSError:
        status = "WARN"
        message = "SSH configuration not found or unreadable."
    results.append(("SSH configuration", status))
    print(f"[{status}] SSH configuration")
    if message:
        print(f"       Reason: {message}")

    # 5. Root-level accounts
    root_accounts = [u.pw_name for u in pwd.getpwall()
                     if u.pw_uid == 0]
    extra_root = [u for u in root_accounts if u != "root"]
    status = "WARN" if extra_root else "PASS"
    results.append(("Root-level accounts", status))
    print(f"[{status}] Root-level accounts")
    if extra_root:
        print("       Reason: Additional UID 0 accounts found.")

    # 6. User accounts
    try:
        users = [u.pw_name for u in pwd.getpwall() if u.pw_uid >= 1000]
        results.append(("User accounts", "PASS"))
        print(f"[PASS] User accounts: found {len(users)} regular accounts.")
    except Exception:
        results.append(("User accounts", "WARN"))
        print("[WARN] User accounts")
        print("       Reason: Could not list local accounts.")

    # 7. Sudo access
    if shutil.which("sudo"):
        check("Sudo access", ["sudo", "-n", "-l"],
              "Sudo permissions could not be checked without a password.")
    else:
        results.append(("Sudo access", "WARN"))
        print("[WARN] Sudo access")
        print("       Reason: sudo command not found.")

    # 8. File permissions
    try:
        mode = os.stat("/etc/shadow").st_mode & 0o777
        if mode & 0o007:
            status = "FAIL"
            message = "/etc/shadow is accessible by others."
        else:
            status = "PASS"
            message = ""
    except OSError:
        status = "WARN"
        message = "Could not inspect /etc/shadow."
    results.append(("File permissions", status))
    print(f"[{status}] File permissions")
    if message:
        print(f"       Reason: {message}")

    # 9. Enabled services
    check("Enabled services",
          ["systemctl", "list-unit-files", "--state=enabled",
           "--type=service", "--no-pager"],
          "Could not list enabled services.")

    # 10. Security logs
    if shutil.which("journalctl"):
        check("Security logs", ["journalctl", "-n", "5", "--no-pager"],
              "Could not read recent system logs.")
    else:
        results.append(("Security logs", "WARN"))
        print("[WARN] Security logs")
        print("       Reason: journalctl not found.")

    print("\n" + "=" * 32)
    print("FINAL SUMMARY")
    for status in ("PASS", "WARN", "FAIL"):
        count = sum(s == status for _, s in results)
        print(f"{status}: {count}")
    print(f"TOTAL: {len(results)}")


if __name__ == "__main__":
    main()
