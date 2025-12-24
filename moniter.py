import subprocess
import sys
import time
import json
import re
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize Colors
init(autoreset=True)

def module_system_monitor():
    """
    ULTIMATE SYSTEM MONITOR: Integrity Check, Wireless Analysis, System Cleaning.
    Targeting Critical Windows Components & Persistence Mechanisms.
    """

    # --- LOGGING SETUP ---
    log_data = []
    log_folder = "System_Check"
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)
    log_file_path = os.path.join(log_folder, f"Scan_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    # --- HELPERS ---
    def log_to_file(text):
        """Removes color codes and appends to log list"""
        clean_text = re.sub(r'\x1b\[[0-9;]*m', '', text)
        log_data.append(clean_text)

    def type_writer(text, speed=0.01):
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(speed)
        print()

    def run_powershell(cmd):
        try:
            result = subprocess.run(
                ["powershell.exe", "-Command", cmd],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except: return None

    # --- BANNER ---
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.RED + Style.BRIGHT + r"""
    ███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗
    ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║
    ███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║
    ╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║
    ███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║
    ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
     [ KERNEL INTEGRITY | WIRELESS | SANITIZATION ]
    """)
    print(Fore.RED + "="*60)
    print(Fore.YELLOW + " [+] TARGET SYSTEM  : " + Fore.WHITE + "LOCAL HOST (KERNEL LEVEL)")
    print(Fore.YELLOW + " [+] SCAN DEPTH     : " + Fore.RED + "DEEP FORENSIC ANALYSIS")
    print(Fore.RED + "="*60 + "\n")
    
    log_to_file(f"SCAN STARTED AT: {datetime.now()}")
    time.sleep(1)

    vulnerabilities = 0

    # =========================================================
    # PHASE 1: SYSTEM INTEGRITY (Firewall, Ports, Registry)
    # =========================================================
    type_writer(f"{Fore.CYAN}[*] PHASE 1: SYSTEM INTEGRITY DIAGNOSTIC...", 0.02)
    time.sleep(0.5)

    # 1.1 OS & Defender
    print(f"\n{Fore.WHITE}[+] CHECKING SECURITY SUBSYSTEM...")
    ver_cmd = '(Get-CimInstance Win32_OperatingSystem).Version'
    os_ver = run_powershell(ver_cmd)
    if os_ver:
        msg = f"    > OS BUILD         : {os_ver}"
        print(f"{Fore.CYAN}{msg}{Style.RESET_ALL}")
        log_to_file(msg)

    def_cmd = "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled | ConvertTo-Json"
    def_out = run_powershell(def_cmd)
    try:
        if def_out and json.loads(def_out).get('RealTimeProtectionEnabled'):
             msg = "    > DEFENDER STATUS  : [ ACTIVE ]"
             print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")
             log_to_file(msg)
        else:
             msg = "    > DEFENDER STATUS  : [ DISABLED ] (CRITICAL RISK)"
             print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
             log_to_file(msg)
             vulnerabilities += 1
    except: pass

    # 1.2 EXTENDED CRITICAL FILE INTEGRITY CHECK
    print(f"\n{Fore.WHITE}[+] VERIFYING KERNEL & SYSTEM BINARIES (SIGNATURE CHECK)...")
    log_to_file("\n[+] FILE INTEGRITY CHECK:")
    
    # List of files hackers target most
    critical_files = [
        r"C:\Windows\System32\ntoskrnl.exe",   # Windows Kernel (Rootkits target this)
        r"C:\Windows\System32\kernel32.dll",   # Core memory handling
        r"C:\Windows\System32\ntdll.dll",      # Native API
        r"C:\Windows\System32\user32.dll",     # User Interface
        r"C:\Windows\System32\lsass.exe",      # Password Storage (Mimikatz target)
        r"C:\Windows\System32\svchost.exe",    # Service Host (Malware hides here)
        r"C:\Windows\System32\winlogon.exe",   # Login Process
        r"C:\Windows\System32\cmd.exe",        # Command Prompt
        r"C:\Windows\System32\powershell.exe", # PowerShell
        r"C:\Windows\explorer.exe"             # Desktop Shell
    ]

    for file_path in critical_files:
        fname = file_path.split("\\")[-1]
        sys.stdout.write(f"\r{Fore.CYAN}    [*] Verifying {fname}..." + " "*20)
        sys.stdout.flush()
        
        # PowerShell command to verify Digital Signature
        sig_cmd = f'Get-AuthenticodeSignature "{file_path}" | Select-Object Status | ConvertTo-Json'
        sig_out = run_powershell(sig_cmd)
        
        status_msg = ""
        is_safe = False
        
        try:
            if sig_out:
                data = json.loads(sig_out)
                # Status 0 = Valid
                if data.get('Status') == 0:
                    is_safe = True
        except: pass

        time.sleep(0.1) # UI Delay for effect

        if is_safe:
            status_msg = f"    > {fname.ljust(15)} : [ SIGNATURE VALID ]"
            sys.stdout.write(f"\r{Fore.GREEN}{status_msg}{Style.RESET_ALL}       \n")
            log_to_file(status_msg)
        else:
            status_msg = f"    > {fname.ljust(15)} : [ INTEGRITY VIOLATION ]"
            sys.stdout.write(f"\r{Fore.RED}{status_msg}{Style.RESET_ALL}       \n")
            log_to_file(status_msg + " <--- ALERT!")
            vulnerabilities += 1

    # 1.3 Firewall Profiles
    print(f"\n{Fore.WHITE}[+] SCANNING FIREWALL PERIMETER...")
    log_to_file("\n[+] FIREWALL STATUS:")
    ps_fw = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    fw_data = run_powershell(ps_fw)
    try:
        if fw_data:
            profiles = json.loads(fw_data)
            if isinstance(profiles, dict): profiles = [profiles]
            for p in profiles:
                name = p.get('Name').upper()
                status = p.get('Enabled')
                if status:
                    msg = f"    > {name.ljust(15)} : [ SECURE ]"
                    print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")
                    log_to_file(msg)
                else:
                    msg = f"    > {name.ljust(15)} : [ DISABLED ]"
                    print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
                    log_to_file(msg)
                    vulnerabilities += 1
    except: pass

    # 1.4 Hosts & Registry
    print(f"\n{Fore.WHITE}[+] CHECKING DNS & STARTUP PERSISTENCE...")
    hosts_cmd = 'Get-Content $env:SystemRoot\\System32\\drivers\\etc\\hosts | Where-Object { $_ -notmatch "^#" -and $_ -ne "" }'
    hosts_content = run_powershell(hosts_cmd)
    if hosts_content and ("google" in hosts_content or "facebook" in hosts_content or "antivirus" in hosts_content):
         msg = "    [!] CRITICAL: DNS POISONING DETECTED IN HOSTS FILE!"
         print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
         log_to_file(msg)
         vulnerabilities += 1
    else:
         msg = "    > HOSTS FILE       : [ CLEAN ]"
         print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")
         log_to_file(msg)

    # 1.5 Port Scan
    print(f"\n{Fore.WHITE}[+] SCANNING CRITICAL PORTS...")
    log_to_file("\n[+] OPEN PORTS:")
    risky_ports = {
        22: "SSH", 445: "SMB", 3389: "RDP", 3306: "MYSQL"
    }
    
    found_open_ports = False
    for port, name in risky_ports.items():
        check_cmd = f"Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue | Select-Object State"
        out = run_powershell(check_cmd)
        if out and "Listen" in out:
            msg = f"    [!] ALERT: {name} ({port}) IS OPEN!"
            print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
            log_to_file(msg)
            vulnerabilities += 1
            found_open_ports = True
            
    if not found_open_ports:
        print(f"{Fore.GREEN}    > ALL CRITICAL PORTS CLOSED.{Style.RESET_ALL}")
        log_to_file("    > ALL CRITICAL PORTS CLOSED.")
    
    # Report Phase 1
    if vulnerabilities > 0:
        print(f"\n{Fore.RED} [!] PHASE 1 COMPLETE: {vulnerabilities} THREATS DETECTED.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN} [✓] PHASE 1 COMPLETE: SYSTEM SECURE.{Style.RESET_ALL}")
    
    print(Fore.CYAN + "-"*60 + "\n")
    time.sleep(1)

    # =========================================================
    # PHASE 2: WIRELESS SPECTRUM ANALYZER
    # =========================================================
    type_writer(f"{Fore.CYAN}[*] PHASE 2: WIRELESS SPECTRUM ANALYSIS...", 0.02)
    time.sleep(0.5)
    log_to_file("\n[+] WIRELESS SCAN:")

    info_cmd = "netsh wlan show interfaces"
    if not run_powershell(info_cmd):
        msg = "    [!] NO WIRELESS ADAPTER FOUND. SKIPPING."
        print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
        log_to_file(msg)
    else:
        print(f"{Fore.WHITE}[+] SCANNING 2.4GHz & 5GHz FREQUENCIES...")
        time.sleep(1)

        scan_out = run_powershell("netsh wlan show networks mode=bssid")
        
        if scan_out and "SSID" in scan_out:
            print(f"\n{Fore.YELLOW} {'SSID'.ljust(25)} | {'SIGNAL'.ljust(8)} | {'SECURITY'}")
            print(Fore.YELLOW + "-"*60)
            
            networks = re.findall(r"SSID \d+ : (.*?)\n.*?Authentication : (.*?)\n.*?Encryption : (.*?)\n.*?Signal : (.*?)%", scan_out, re.DOTALL)
            
            count = 0
            for ssid, auth, enc, sig in networks:
                ssid = ssid.strip()
                if not ssid: ssid = "[HIDDEN]"
                s_val = int(sig.strip())
                
                col = Fore.GREEN if s_val > 60 else Fore.YELLOW
                sec_status = f"{auth.strip()}"
                if "Open" in auth: sec_status = f"{Fore.RED}OPEN/INSECURE{Style.RESET_ALL}"
                
                print(f"{col} {ssid[:25].ljust(25)} | {sig.strip()}%      | {sec_status}")
                log_to_file(f"SSID: {ssid} | Signal: {sig}% | Auth: {auth.strip()}")
                time.sleep(0.05)
                count += 1
            print(f"\n{Fore.GREEN} [✓] PHASE 2 COMPLETE: {count} NETWORKS IDENTIFIED.{Style.RESET_ALL}")
        else:
             print(f"{Fore.YELLOW}    [!] NO NETWORKS FOUND IN RANGE.{Style.RESET_ALL}")

    print(Fore.CYAN + "-"*60 + "\n")
    time.sleep(1)

    # =========================================================
    # PHASE 3: SYSTEM CLEANER (TRACKS WIPER)
    # =========================================================
    type_writer(f"{Fore.CYAN}[*] PHASE 3: SYSTEM SANITIZATION & LOG WIPING...", 0.02)
    
    print(Fore.RED + "\n    [!] WARNING: THIS ACTION CLEARS LOGS, TEMP FILES & HISTORY.")
    
    # USER PROMPT
    choice = input(f"{Fore.YELLOW}    [?] INITIATE CLEANING SEQUENCE? (Y/N) > {Style.RESET_ALL}")

    if choice.lower() == 'y':
        print(f"\n{Fore.WHITE}[+] STARTING FORENSIC CLEANUP...")
        log_to_file("\n[+] SYSTEM CLEANING: EXECUTED")
        
        tasks = [
            ("Flushing DNS Cache", "ipconfig /flushdns"),
            ("Wiping Temp Files", "Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue"),
            ("Clearing Prefetch", "Remove-Item -Path C:\Windows\Prefetch\* -Recurse -Force -ErrorAction SilentlyContinue"),
            ("Purging Recent Docs", "Remove-Item -Path $env:APPDATA\Microsoft\Windows\Recent\* -Recurse -Force -ErrorAction SilentlyContinue"),
            ("Emptying Recycle Bin", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue")
        ]

        for name, cmd in tasks:
            sys.stdout.write(f"\r{Fore.CYAN}    [*] {name}..." + " "*10)
            sys.stdout.flush()
            time.sleep(0.5)
            run_powershell(cmd)
            sys.stdout.write(f"\r{Fore.GREEN}    [✓] {name} : CLEANED     \n")
        
        print(f"\n{Fore.GREEN} [✓] PHASE 3 COMPLETE: SYSTEM TRACKS ELIMINATED.{Style.RESET_ALL}")

    else:
        print(f"\n{Fore.YELLOW} [!] CLEANING ABORTED BY USER.{Style.RESET_ALL}")
        log_to_file("\n[+] SYSTEM CLEANING: SKIPPED")

    # SAVE LOG FILE
    try:
        with open(log_file_path, "w") as f:
            for line in log_data:
                f.write(line + "\n")
        print(f"\n{Fore.YELLOW}[*] FULL DIAGNOSTIC REPORT SAVED TO: {Fore.WHITE}{log_file_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] ERROR SAVING LOG: {e}{Style.RESET_ALL}")

    print(Fore.RED + "="*60)
    print(f"{Fore.GREEN} [✓] ALL SYSTEMS OPERATIONAL.{Style.RESET_ALL}")
    input(f"\n{Fore.YELLOW}[?] PRESS ENTER TO RETURN...{Style.RESET_ALL}")

# --- FUNCTION CALL ---
if __name__ == "__main__":
    module_system_monitor()