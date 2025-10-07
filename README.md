# CTF PIN Bruteforcer

Simple, fast, and robust 4-digit PIN brute-forcer intended for CTF practice and authorized testing only. Supports GET or POST, HTTPS, concurrent workers, retries with exponential backoff, and live attempt output with permanent success lines.

## Features
- Brute-forces 4-digit PINs (0000–9999)
- GET or POST request support
- Optional HTTPS
- Configurable concurrency (ThreadPool)
- Timeouts, retries and exponential backoff
- Per-thread delay option for rate limiting
- Live single-line attempt updates; found flags printed as permanent lines
- Optional `--stop-on-found` to exit on first success
- Small ASCII banner and short description on start

## Usage
Interactive:
python3 pin_bruteforce.py
# follow prompts for host, port, endpoint and param
CLI:

python3 pin_bruteforce.py --host 127.0.0.1 --port 8000 --endpoint /pin --param pin --threads 20 --timeout 3


Common flags:

--method GET|POST (default: GET)

--https (use HTTPS)

--threads (concurrent workers)

--timeout (seconds)

--delay (seconds between attempts per thread)

--retries (retry transient failures)

--flag-key (JSON key to look for the flag)

--stop-on-found (stop after first success)

Example

Start a run against http://10.0.0.5:9000/pin checking query param pin with 30 threads:

python3 pin_bruteforce.py -H 10.0.0.5 -P 9000 -e /pin -k pin -t 30

Legal / Safety

Only run this tool against systems you own or have explicit permission to test (CTF targets you control or event hosts). Unauthorized brute force or penetration testing is illegal and unethical. Use responsibly.
