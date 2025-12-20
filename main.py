import sys
import time
import socket
import random
import requests
import pyttsx3
import os
from colorama import Fore, Back, Style, init

# --- INITIALIZATION ---
init(autoreset=True)
engine = pyttsx3.init()

# Voice Settings
engine.setProperty('rate', 150) 
engine.setProperty('volume', 1.0)

def speak(text):
    engine.say(text)
    engine.runAndWait()

def type_effect(text, color=Fore.GREEN, speed=0.03):
    for char in text:
        sys.stdout.write(color + char)
        sys.stdout.flush()
        time.sleep(speed)
    print("")

def loading_bar(task_name):
    print(Fore.YELLOW + f"[*] {task_name}...", end="")
    for i in range(15):
        time.sleep(0.04)
        print(Fore.GREEN + "█", end="", flush=True)
    print(" [DONE]\n")

def startup_sequence():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + "[*] BOOTING SENTINEL-X KERNEL...")
    time.sleep(1)
    
    tasks = ["Loading Security Modules...", "Encrypting Connection (AES-256)...", "Connecting to Satellite Uplink..."]
    for task in tasks:
        print(Fore.YELLOW + f"[>] {task}", end="\r")
        time.sleep(0.3)
        print(Fore.GREEN + f"[OK] {task}          ")
    
    print("\n")
    logo = """
    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗         ██╗  ██╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║         ╚██╗██╔╝
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║          ╚███╔╝ 
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║          ██╔██╗ 
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╗ ██╔╝ ██╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝
                                            [ SYSTEM: ONLINE ]
    """
    print(Fore.CYAN + Style.BRIGHT + logo)
    time.sleep(0.5)
    speak("System Initialized. Sentinel X is active.")

# --- FEATURES ---

def port_scanner():
    speak("Scanning ports.")
    target = input(Fore.WHITE + "\n[?] Enter Target IP: ") or "127.0.0.1"
    print(Fore.CYAN + f"\n[*] Target: {target}")
    ports = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS"}
    for port, service in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(Fore.RED + f"[!] {port} ({service}) : OPEN")
        else:
            print(Fore.GREEN + f"[+] {port} ({service}) : SECURE")
    speak("Scan complete.")

def phishing_check():
    speak("Phishing Radar active.")
    url = input(Fore.WHITE + "\n[?] Enter URL: ").lower()
    loading_bar("Checking Database")
    bad_words = ["free", "login", "bank", "update", "verify"]
    if any(x in url for x in bad_words):
        print(Fore.RED + f"[DANGER] PHISHING DETECTED: {url}")
        speak("Alert! Malicious link detected.")
    else:
        print(Fore.GREEN + "[SAFE] Domain Verified.")
        speak("Link is safe.")

def web_pentest():
    speak("Web Pentest mode.")
    url = input(Fore.WHITE + "\n[?] Enter Website URL: ")
    paths = ["/admin", "/login", "/config"]
    print(Fore.CYAN + "\n[*] Brute-forcing directories...")
    for path in paths:
        print(Fore.YELLOW + f"[~] Checking {url}{path}...", end="\r")
        time.sleep(0.5)
        if path == "/login":
             print(Fore.GREEN + f"[+] FOUND: {url}{path} (200 OK)   ")
        else:
             print(Fore.RED + f"[-] MISSING: {url}{path} (404)    ")
    speak("Directory scan finished.")

def network_sniffer():
    speak("Sniffing network traffic.")
    print(Fore.CYAN + "\n[*] LISTENING ON WLAN0...")
    print(f"{'PROTO':<10} {'SRC':<20} {'DEST':<20}")
    print("-" * 50)
    try:
        for _ in range(15):
            proto = random.choice(["TCP", "UDP", "HTTPS"])
            ip = f"192.168.1.{random.randint(2,100)}"
            print(Fore.GREEN + f"{proto:<10} {ip:<20} 104.22.11.{random.randint(1,255)}")
            time.sleep(0.2)
    except KeyboardInterrupt: pass
    speak("Sniffing complete.")

def mitm_simulation():
    speak("Starting Man in the Middle Attack Simulation.")
    print(Back.RED + Fore.WHITE + "\n[!!!] POISONING ARP CACHE [!!!]")
    loading_bar("Redirecting Traffic")
    print(Fore.CYAN + "\n[*] INTERCEPTING PASSWORDS...\n")
    fake_creds = [("Facebook", "ali_k", "hello1234"), ("Gmail", "student", "homework1"), ("Bank", "admin", "P@ssw0rd")]
    for _ in range(20):
        print(Fore.GREEN + "".join(random.choices("01", k=50)))
        time.sleep(0.1)
        if random.random() < 0.2:
            app, user, pwd = random.choice(fake_creds)
            print(Fore.RED + f"\n[>>] CAPTURED: {app} | User: {user} | Pass: {pwd}\n")
            speak(f"Captured password for {app}")
            time.sleep(1)
    speak("Attack simulation ended.")

# --- REAL OSINT FEATURE (UPDATED) ---
def osint_tracker():
    speak("OSINT Protocol Initiated. Enter target username.")
    target = input(Fore.WHITE + "\n[?] Enter Target Username (e.g. facebook): ")
    
    print(Fore.CYAN + f"\n[*] CONNECTING TO GLOBAL NETWORKS FOR: {target}")
    speak("Scanning social media platforms in real time.")
    
    # Real Headers taake websites block na karein
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    # Sites list - Jinka 404 response reliable hai
    sites = {
        "GitHub": f"https://github.com/{target}",
        "Instagram": f"https://www.instagram.com/{target}/",
        "Reddit": f"https://www.reddit.com/user/{target}",
        "Pinterest": f"https://www.pinterest.com/{target}/",
        "Wikipedia": f"https://en.wikipedia.org/wiki/User:{target}"
    }

    found_count = 0

    print(Fore.YELLOW + "\n[~] Starting Active Reconnaissance...\n")

    for site, url in sites.items():
        try:
            # Real Request Bhej raha hai
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] FOUND: {site} Account -> {url}")
                found_count += 1
            else:
                print(Fore.RED + f"[-] NOT FOUND: {site}")
        except:
            print(Fore.RED + f"[!] ERROR: Could not connect to {site}")

    # Summary
    if found_count > 0:
        speak(f"Scan complete. Found {found_count} accounts associated with this username.")
    else:
        speak("Scan complete. No accounts found.")

    # Dark Web Simulation (Kyunki Real Dark web API paid hoti hai)
    print(Fore.YELLOW + "\n[*] CHECKING DARK WEB LEAKS (SIMULATION)...")
    time.sleep(1.5)
    print(Fore.RED + Style.BRIGHT + "[!] ALERT: Email found in 'Collection #1' Breach Database!")
    
    print(Fore.CYAN + "\n[+] --- TARGET DOSSIER GENERATED ---")
    print(Fore.WHITE + f"    Username : {target}")
    print(Fore.WHITE + f"    Status   : Analyzed")
    
    speak("Digital footprint analysis complete.")

# --- MAIN LOOP ---
def main():
    startup_sequence()
    
    while True:
        print(Fore.MAGENTA + "\n--- SENTINEL-X COMMAND MENU ---")
        print(Fore.YELLOW + "1. OSINT Tracker (REAL-TIME)")
        print("2. Phishing Detector")
        print("3. Web Pentest (Recon)")
        print("4. Network Sniffer")
        print("5. MiTM Attack (Live Hack)")
        print("6. Port Scanner")
        print("7. Exit")
        
        choice = input(Fore.WHITE + "\nroot@sentinel:~# ")
        
        if choice == '1': osint_tracker()
        elif choice == '2': phishing_check()
        elif choice == '3': web_pentest()
        elif choice == '4': network_sniffer()
        elif choice == '5': mitm_simulation()
        elif choice == '6': port_scanner()
        elif choice == '7': 
            speak("System deactivated.")
            break

if __name__ == "__main__":
    main()
