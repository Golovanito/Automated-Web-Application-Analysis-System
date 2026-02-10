import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from awsas.cve.sync import sync_from_file
import sys
import time

def main():
    db_path = "data/cve_store.db"
    json_files = [
        "data/nvdcve-2.0-2014.json",
        "data/nvdcve-2.0-2015.json",
        "data/nvdcve-2.0-2016.json",
        "data/nvdcve-2.0-2017.json",
        "data/nvdcve-2.0-2018.json",
        "data/nvdcve-2.0-2019.json",
        "data/nvdcve-2.0-2021.json",
        "data/nvdcve-2.0-2022.json",
        "data/nvdcve-2.0-2023.json",
        "data/nvdcve-2.0-2024.json",
    ]

    start = time.time()
    for jf in json_files:
        print(f"[+] Syncing {jf} -> {db_path}")
        sync_from_file(db_path, jf)
    print("[+] Done. Time:", time.time() - start)

if __name__ == "__main__":
    main()