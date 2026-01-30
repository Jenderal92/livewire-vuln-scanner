#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import requests
import re
import sys
import threading
from multiprocessing.dummy import Pool as ThreadPool

reload(sys)
sys.setdefaultencoding('utf-8')

requests.packages.urllib3.disable_warnings()

THREADS = 15
OUTPUT_FILE = 'vuln.txt'

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/120.0 Safari/537.36',
    'Accept': '*/*',
    'Connection': 'close'
}

VERSION_PATTERNS = [
    r'livewire[ /-]v?([\d\.]+)',
    r'livewire\.js\?.*v=([\d\.]+)',
    r'livewire/([\d\.]+)/livewire',
    r'Livewire\s+v?([\d\.]+)'
]

file_lock = threading.Lock()


def banner():
    print("""
=========================================
  Livewire Passive Vulnerability Scanner
  Python 2.7 | Multithread | Realtime Save
  Check: Livewire < 3.6.4
=========================================
""")

def version_less_than(v1, v2):
    try:
        return map(int, v1.split('.')) < map(int, v2.split('.'))
    except:
        return False

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def extract_domain(url):
    if '://' in url:
        url = url.split('://', 1)[1]
    return url.split('/', 1)[0]

def scan(target):
    raw = target.strip()
    url = normalize_url(raw)
    domain = extract_domain(url)

    try:
        r = requests.get(
            url,
            headers=HEADERS,
            timeout=10,
            verify=False,
            allow_redirects=True
        )

        content = r.text

        for pattern in VERSION_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)

                if version_less_than(version, '3.6.4'):
                    print('[+] VULN  : ' + domain + ' | Livewire ' + version)

                    with file_lock:
                        with open(OUTPUT_FILE, 'a') as f:
                            f.write(domain + '\n')

                else:
                    print('[-] SAFE  : ' + domain + ' | Livewire ' + version)
                break

    except Exception:
        print('[!] ERROR : ' + domain)

# ================= MAIN =================
def main():
    if len(sys.argv) != 2:
        print('Usage: python %s list.txt' % sys.argv[0])
        sys.exit(1)

    banner()

    infile = sys.argv[1]

    with open(infile) as f:
        targets = [line.strip() for line in f if line.strip()]

    print('[*] Total targets : ' + str(len(targets)))
    print('[*] Threads       : ' + str(THREADS))
    print('[*] Output file   : ' + OUTPUT_FILE)
    print('[*] Starting scan...\n')

    pool = ThreadPool(THREADS)
    pool.map(scan, targets)
    pool.close()
    pool.join()

    print('\n=========================================')
    print('[✓] Scan finished')
    print('[✓] Results saved to ' + OUTPUT_FILE)
    print('=========================================')

if __name__ == '__main__':
    main()
