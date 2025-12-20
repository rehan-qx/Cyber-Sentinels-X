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

# --- DEPENDENCY CHECK ---
try:
    from scapy.all import sniff, ARP, Ether, srp, conf
    conf.verb = 0 
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# --- SYSTEM INIT ---
init(autoreset=True)
engine = pyttsx3.init()
engine.setProperty('rate', 160) 
engine.setProperty('volume', 1.0)

# --- UTILITIES ---
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
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╗██╗██╔╝ ██╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝╚═╝╚═╝  ╚═╝
                                            [ SYSTEM: ONLINE ]
    """
    print(Fore.CYAN + Style.BRIGHT + logo)
    speak("Sentinel X interface loaded.")

# --- 1. REAL OSINT TRACKER (30+ SITES) ---
def osint_tracker():
    speak("Global OSINT Tracker initialized.")
    target = input(Fore.WHITE + "\nroot@sentinel:~/osint# Target Username: ")
    
    print(Fore.CYAN + "\n[*] Initializing Search Threads for 30+ Platforms...")
    print(Fore.CYAN + "[*] Please wait, checking databases...\n")
    
    # Headers to mimic a real browser (prevents blocking)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    # 30+ Real URLs
    sites = {
        "GitHub": f"https://github.com/{target}",
        "Instagram": f"https://www.instagram.com/{target}/",
        "Twitter": f"https://twitter.com/{target}",
        "Facebook": f"https://www.facebook.com/{target}",
        "Reddit": f"https://www.reddit.com/user/{target}",
        "TikTok": f"https://www.tiktok.com/@{target}",
        "Pinterest": f"https://www.pinterest.com/{target}/",
        "Telegram": f"https://t.me/{target}",
        "GitLab": f"https://gitlab.com/{target}",
        "BitBucket": f"https://bitbucket.org/{target}/",
        "Medium": f"https://medium.com/@{target}",
        "WordPress": f"https://{target}.wordpress.com/",
        "Patreon": f"https://www.patreon.com/{target}",
        "Vimeo": f"https://vimeo.com/{target}",
        "SoundCloud": f"https://soundcloud.com/{target}",
        "Spotify": f"https://open.spotify.com/user/{target}",
        "Steam": f"https://steamcommunity.com/id/{target}",
        "Twitch": f"https://www.twitch.tv/{target}",
        "Roblox": f"https://www.roblox.com/user.aspx?username={target}",
        "DeviantArt": f"https://www.deviantart.com/{target}",
        "Behance": f"https://www.behance.net/{target}",
        "Dribbble": f"https://dribbble.com/{target}",
        "Flickr": f"https://www.flickr.com/people/{target}/",
        "Pastebin": f"https://pastebin.com/u/{target}",
        "Wikipedia": f"https://en.wikipedia.org/wiki/User:{target}",
        "HackerNews": f"https://news.ycombinator.com/user?id={target}",
        "About.me": f"https://about.me/{target}",
        "Blogger": f"https://{target}.blogspot.com",
        "Replit": f"https://replit.com/@{target}",
        "Gumroad": f"https://gumroad.com/{target}",
        "ProductHunt": f"https://www.producthunt.com/@{target}",
        "Wattpad": f"https://www.wattpad.com/user/{target}",
        "Canva": f"https://www.canva.com/p/{target}",
        "CodePen": f"https://codepen.io/{target}"
    }

    found_list = []
    
    # Threaded Function for Speed
    def check_site(site, url):
        try:
            r = requests.get(url, headers=headers, timeout=5)
            # Most sites return 200 if found. Some (like TikTok) might require specific handling, 
            # but 200 vs 404 is the standard check.
            if r.status_code == 200:
                print(Fore.GREEN + f"[+] DETECTED: {site:<15} -> {url}")
                found_list.append(site)
            elif r.status_code == 404:
                # Optional: Print missing sites in Red if you want verbose output
                # print(Fore.RED + f"[-] {site:<15} : NOT FOUND") 
                pass
        except:
            pass # Ignore connection errors

    # Launch Threads
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

# --- 3. REAL WEB RECON ---
def web_pentest():
    speak("Web Recon initiated.")
    target = input(Fore.WHITE + "\nroot@sentinel:~/web# Enter URL: ")
    if not target.startswith("http"): target = "http://" + target

    try:
        print(Fore.YELLOW + "[*] Fingerprinting Server...")
        r = requests.get(target, timeout=5)
        print(Fore.CYAN + f"    Server: {r.headers.get('Server', 'Hidden')}")
        print(Fore.CYAN + f"    Tech  : {r.headers.
 TECH) ---
def web_pentest():
    speak("Web Reconnaissance Mode.")
    target = input(Fore.WHITE + "\nroot@sentinel:~/web# Enter Target IP/URL: ")
    if not target.startswith("http"): target = "http://" + target
    
    log(f"Sending HTTP Probes to {target}...", "INFO")
    
    try:
        r = requests.get(target, timeout=5)
        
        # 1. Server Fingerprinting
        headers = r.headers
        server = headers.get("Server", "Unknown")
        powered = headers.get("X-Powered-By", "Hidden")
        
        print(Fore.GREEN + "\n--- SERVER FINGERPRINT ---")
        print(f"{Fore.YELLOW}Server OS   : {Fore.WHITE}{server}")
        print(f"{Fore.YELLOW}Technology  : {Fore.WHITE}{powered}")
        print(f"{Fore.YELLOW}Cookies     : {Fore.WHITE}{len(r.cookies)} Detected")
        
        # 2. Check for Admin Panels (Real requests)
        print(Fore.CYAN + "\n[*] Scanning for Sensitive Directories...")
        paths = ["/admin", "/login", "/wp-admin", "/robots.txt", "/config"]
        
        for path in paths:
            check_url = target + path
            code = requests.head(check_url).status_code
            if code == 200:
                print(Fore.GREEN + f"[+] EXPOSED: {path:<15} (200 OK)")
            elif code == 403:
                print(Fore.YELLOW + f"[!] FORBIDDEN: {path:<15} (403 Blocked)")
            else:
                print(Fore.RED + f"[-] MISSING: {path:<15} ({code})")

    except Exception as e:
        log(f"Target unreachable: {e}", "ERROR")

# --- 4. REAL NETWORK SNIFFER (SCAPY) ---
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
        # Sniffs 20 packets then stops to avoid freezing loop
        sniff(prn=packet_callback, count=25)
        speak("Capture buffer full. Stopping.")
    except PermissionError:
        log("Run as Administrator to sniff packets!", "ERROR")

# --- 5. REAL ARP NETWORK SCANNER (Replaces Fake MITM) ---
def mitm_simulation():
    # Changed from "Fake Password Hack" to "Real Network Mapping"
    # This is the first step of a real MITM attack (Target Discovery)
    if not SCAPY_AVAILABLE:
        log("Scapy required.", "ERROR"); return

    speak("Scanning Local Network for Active Devices.")
    target_ip = input(Fore.WHITE + "\nroot@sentinel:~/mitm# Enter Gateway IP (e.g. 192.168.1.1/24): ")
    
    log("Broadcasting ARP Requests...", "INFO")
    
    try:
        # Create ARP packet
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Send and receive
        result = srp(packet, timeout=3, verbose=0)[0]
        
        print(Fore.GREEN + "\nIP ADDRESS\t\tMAC ADDRESS")
        print("-----------------------------------------")
        for sent, received in result:
            print(f"{Fore.CYAN}{received.psrc}\t\t{Fore.WHITE}{received.hwsrc}")
        
        speak(f"Scan complete. Found {len(result)} devices.")

    except Exception as e:
        log(f"Scan Failed: {e}", "ERROR")

# --- 6. REAL MULTI-THREADED PORT SCANNER ---
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

    # Scanning top 100 ports for speed
    threads = []
    for port in range(1, 101):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
    
    for t in threads: t.join()
    
    if not active_ports:
        log("No open ports found or firewall active.", "WARN")
    speak("Port scan finished.")

# --- MAIN LOOP ---
def main():
    startup_sequence()
    
    while True:
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

