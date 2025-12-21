import os
import json
import requests
import socket
import time
import textwrap
import google.generativeai as genai
from fpdf import FPDF
from datetime import datetime
from urllib.parse import urlparse

# --- CONFIGURATION (API KEYS) ---
URLSCAN_API_KEY = "019b3d5b-2b60-7409-911e-28acaad1448f"
VIEWDNS_API_KEY = "92c5506b68d5884bdfda2774ecd02bd5544caebd"
GEMINI_API_KEY = "AIzaSyBTkkuwHjQgGK2SRmMPkPnDRZ2sfGsTY-4"
THUM_IO_AUTH = "76073-bbd919f27b3be431bd9965e2ff71de93" 

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
    #           [ Powered by AI & ML ]                             #
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
    """Removes http, https, www, and trailing paths to get pure domain"""
    target = target.strip()
    # Remove protocol
    if target.startswith("https://"):
        target = target[8:]
    elif target.startswith("http://"):
        target = target[7:]
    
    # Remove trailing paths (like /express/)
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
    log_step("Initializing AI Security Analyst...", 1)
    
    prompt = f"""
    You are an expert Cyber Security Analyst. Analyze the following reconnaissance data for a target (Domain/IP).
    
    RAW DATA:
    {json.dumps(data_json, indent=2)}
    
    TASK:
    1. Determine if the target is SAFE, SUSPICIOUS, or MALICIOUS.
    2. Write a professional report in English.
    3. Highlight open ports, vulnerabilities, reputation, and missing security headers.
    4. Provide a final verdict.
    
    FORMAT:
    - Executive Summary
    - Key Technical Findings
    - Risk Assessment
    - Final Verdict (SAFE/SUSPICIOUS)
    """
    
    try:
        model = genai.GenerativeModel('gemini-2.5-flash-preview-09-2025')
        log_step("Sending data to AI for analysis...", 2)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        log_step(f"AI Analysis Failed: {str(e)}", "error")
        return "AI Analysis could not be completed due to an API error."

# --- DATA MODULES ---

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
    for i in range(3):
        payload[f"columns[{i}][data]"] = str(i)
        payload[f"columns[{i}][searchable]"] = "true"
        payload[f"columns[{i}][orderable]"] = "false"
    headers = {'User-Agent': 'Mozilla/5.0', 'X-Requested-With': 'XMLHttpRequest', 'Referer': f'https://phishs.com/check-domain/{domain}'}
    try:
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
    log_step("Scanning Open Ports...", 2)
    try:
        r = requests.get(f"{base_url}/portscan/?host={target}&apikey={VIEWDNS_API_KEY}&output=json")
        results['open_ports'] = r.json().get('response', {})
    except: results['open_ports'] = "Error"
    
    log_step("Checking Abuse Database...", 2)
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
        r = requests.get(url)
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

# --- MAIN LOGIC ---
def run_recon_process(raw_input, mode):
    print_banner()
    
    # --- CLEAN INPUT ---
    # Removes http, https, slashes to avoid OSError
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
        else:
            log_step("Could not resolve IP", "error")
        
        full_data["dns"] = module_phishs_dns(target)
        full_data["viewdns"] = module_viewdns(target, ip)
        full_data["history_scans"] = module_urlscan(target)
        full_data["certs"] = module_crtsh(target)

    # 3. SCREENSHOTS ENGINE
    log_step("Engaging Screenshot Engine...", 1)

    # A. Historical
    if full_data["history_scans"]:
        log_step("Downloading Historical Screenshots...", 2)
        for i, item in enumerate(full_data["history_scans"]):
            if i >= 3: break
            url = item.get("screenshot_url")
            if url:
                fname = f"History_Shot_{i+1}.png"
                path = download_image(url, screenshots_folder, fname)
                if path: log_step(f"Saved: {fname}", 3)

    # B. Live (Thum.io)
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

    print_dict(clean_data)
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
    print(ai_verdict)
    print(Colors.CYAN + "="*60 + Colors.ENDC)
    log_step("SCAN COMPLETE.", 1)

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