# scripts/init_cve_store.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from awsas.cve.sync import sync_from_file
import sys
import time

def main():
    db_path = "data/cve_store.db"
    json_files = [
        "data/nvdcve-2.0-2013.json",
        "data/nvdcve-2.0-2025.json",
        "data/nvdcve-2.0-2020.json",
        "data/nvdcve-2.0-recent.json"
    ]

    start = time.time()
    for jf in json_files:
        print(f"[+] Syncing {jf} -> {db_path}")
        sync_from_file(db_path, jf)
    print("[+] Done. Time:", time.time() - start)

if __name__ == "__main__":
    main()