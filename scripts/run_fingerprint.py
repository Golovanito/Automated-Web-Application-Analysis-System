# run_fingerprint.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import argparse
import json
import sys
import logging



try:
    from awsas.fingerprint.detector import FingerprintDetector
except Exception:
    try:
        from awsas.fingerprint import FingerprintDetector
    except Exception as e:
        print("Nie udało się zaimportować FingerprintDetector:", e)
        sys.exit(1)

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

def main():
    setup_logging()
    p = argparse.ArgumentParser(description="Run fingerprint on a target URL")
    p.add_argument("url", help="Target URL to fingerprint (e.g. https://example.com)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    args = p.parse_args()

    det = FingerprintDetector(timeout=args.timeout)
    #print(f"[+] Starting fingerprint for: {args.url}")
    profile = det.analyze(args.url)

    # print pretty json
    output = profile.to_dict() if hasattr(profile, "to_dict") else profile.__dict__
    print(json.dumps(output, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()