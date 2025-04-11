import os
import time
import logging

logging.basicConfig(filename='attack_tool.log', level=logging.INFO)

def type_slow(msg):
    for char in msg:
        print(char, end='', flush=True)
        time.sleep(0.01)
    print()

def save_attack_report(target_info, attacks):
    with open("attack_summary.txt", "w") as f:
        f.write("Target Profile:\n")
        for key, value in target_info.items():
            f.write(f"{key}: {value}\n")
        f.write("\nRecommended Attacks:\n")
        for attack in attacks:
            f.write(f"- {attack}\n")

def target_profiling():
    type_slow("\n=== Enhanced Target Profiling ===\n")

    questions = [
        ("os", "Enter the target operating system (e.g., Linux, Windows, macOS): ", str.lower),
        ("service", "Enter the target service type (e.g., web, ssh, ftp, database, smtp, smb): ", str.lower),
        ("version", "Enter the service version (if known, e.g., 2.2.1): ", lambda x: x or "n/a"),
        ("authentication", "Does the service require authentication? (yes/no): ", lambda x: x.lower() == "yes"),
        ("firewall", "Is there a firewall in place? (yes/no): ", lambda x: x.lower() == "yes"),
        ("internal", "Is the target on an internal network? (yes/no): ", lambda x: x.lower() == "yes"),
        ("port", "Enter the port number (optional): ", lambda x: x or None),
        ("is_outdated", "Is the service version outdated or vulnerable? (yes/no): ", lambda x: x.lower() == "yes"),
        ("is_virtualized", "Is the service running in a virtual machine or container? (yes/no): ", lambda x: x.lower() == "yes"),
        ("is_encrypted", "Is HTTPS or encryption being used? (yes/no): ", lambda x: x.lower() == "yes"),
        ("known_users", "Enter any known user account (optional): ", lambda x: x or None),
        ("known_vulns", "List any known CVEs or software vulnerabilities (optional): ", lambda x: x or None)
    ]

    target_info = {}
    for key, prompt, transform in questions:
        user_input = input(prompt).strip()
        target_info[key] = transform(user_input)

    return target_info

def attack_selection(target_info):
    type_slow("\n[+] Analyzing target information for optimal attack vectors...")

    attacks = []

    svc = target_info["service"]
    os_type = target_info["os"]
    auth = target_info["authentication"]
    fw = target_info["firewall"]
    internal = target_info["internal"]
    outdated = target_info["is_outdated"]
    vuln = target_info["known_vulns"]
    users = target_info["known_users"]
    encrypted = target_info["is_encrypted"]
    virtualized = target_info["is_virtualized"]

    web_attacks = ["web_exploit", "dir_enum", "xss"]
    ssh_attacks = ["ssh_attack", "ssh_enum"]
    ftp_attacks = ["ftp_attack", "ftp_enum"]
    db_attacks = ["sql_injection", "db_enum"]
    smtp_attacks = ["smtp_enum", "spoofing"]
    smb_attacks = ["smb_enum", "smb_relay"]

    if svc == "web":
        attacks += web_attacks
        if auth: attacks.append("brute_force")
        if not fw: attacks.append("direct_access")
        if internal: attacks.append("internal_recon")
        if encrypted: attacks.append("https_mitm")
    elif svc == "ssh":
        attacks += ssh_attacks
        if not auth: attacks.append("default_credentials")
    elif svc == "ftp":
        attacks += ftp_attacks
        if not auth: attacks.append("anonymous_access")
    elif svc == "database":
        attacks += db_attacks
        if not auth: attacks.append("default_credentials")
    elif svc == "smtp":
        attacks += smtp_attacks
        if not auth: attacks.append("open_relay_test")
    elif svc == "smb":
        attacks += smb_attacks
        if not auth: attacks.append("guest_access")
    else:
        attacks.append("general_recon")

    if os_type == "windows":
        attacks.append("windows_privilege_escalation")
    elif os_type == "linux":
        attacks.append("linux_privilege_escalation")

    if outdated: attacks.append("version_specific_exploit")
    if vuln: attacks.append("cve_exploit")
    if users: attacks.append("user_targeted_brute")
    if virtualized: attacks.append("vm_escape")

    return attacks

def display_attacks(attacks):
    type_slow("\n[+] Potential Attacks Identified:")
    examples = {
        "web_exploit": "curl -X POST http://target/vuln -d 'cmd=id'",
        "brute_force": "hydra -l user -P pass.txt target http-post-form '/login.php:username=^USER^&password=^PASS^:Invalid login'",
        "direct_access": "curl http://target/admin/config.php",
        "internal_recon": "nmap -sn 192.168.1.0/24",
        "dir_enum": "gobuster dir -u http://target -w wordlist.txt",
        "xss": "curl -X GET 'http://target/search?q=<script>alert(1)</script>'",

        "ssh_attack": "nmap -p 22 --script ssh-brute target",
        "ssh_enum": "nmap -p 22 --script ssh-auth-methods target",
        "default_credentials": "ssh root@target",

        "ftp_attack": "nmap -p 21 --script ftp-brute target",
        "anonymous_access": "ftp target",
        "ftp_enum": "nmap -p 21 --script ftp-anon target",

        "sql_injection": "sqlmap -u 'http://target/vuln.php?id=1' --dbs",
        "db_enum": "nmap -p 3306 --script mysql-info target",

        "smtp_enum": "nmap --script smtp-enum-users -p 25 target",
        "open_relay_test": "swaks --to test@example.com --from attacker@example.com --server target",
        "spoofing": "sendEmail -f attacker@target -t victim@target -s smtp.target.com",

        "smb_enum": "nmap -p 445 --script smb-enum-shares target",
        "smb_relay": "impacket-smbrelayx -h",
        "guest_access": "smbclient //target/share -N",

        "general_recon": "nmap -A target",
        "windows_privilege_escalation": "powershell -ExecutionPolicy Bypass -File PowerUp.ps1 -AllChecks",
        "linux_privilege_escalation": "bash LinEnum.sh",

        "version_specific_exploit": "searchsploit service_name version",
        "cve_exploit": "msfconsole -x 'use exploit/example; set RHOSTS target; run'",
        "user_targeted_brute": "hydra -l known_user -P common.txt target",
        "https_mitm": "mitmproxy -p 8080",
        "vm_escape": "searchsploit -t 'vm escape'"
    }

    for attack in attacks:
        type_slow(f" - {attack}")
        type_slow(f"   Example command: {examples.get(attack, '[No example available]')}")

def main():
    type_slow("============================")
    type_slow("   Automated Attack Menu")
    type_slow("============================\n")

    while True:
        try:
            target_info = target_profiling()
            attacks = attack_selection(target_info)

            if attacks:
                display_attacks(attacks)
                save_attack_report(target_info, attacks)
                logging.info("Attack report saved successfully.")
            else:
                type_slow("[-] No valid attack paths identified. Consider manual enumeration.")

            ask_again = input("\nWould you like to analyze another target? (yes/no): ").strip().lower()
            if ask_again != "yes":
                type_slow("[+] Exiting. Stay sneaky, hacker friend. ⌐■_■")
                break
        except KeyboardInterrupt:
            type_slow("\n[-] Interrupted by user. Gracefully shutting down...")
            break
        except Exception as e:
            type_slow(f"\n[!] Unexpected error occurred: {str(e)}")
            logging.error(f"Unexpected error: {str(e)}")
            break

# 👇 FIX: Always wait before closing the window
if __name__ == "__main__":
    try:
        main()
    finally:
        input("\n[Press Enter to close this window...]")
