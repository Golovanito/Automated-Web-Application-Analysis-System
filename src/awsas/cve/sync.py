import json
from typing import List, Dict, Any
from .store import CVEStore
import os

def load_json_file(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "CVE_Items" in data:
        return data["CVE_Items"]
    if isinstance(data, dict) and "vulnerabilities" in data:
        return data["vulnerabilities"]
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported CVE JSON format")

def sync_from_file(db_path: str, json_path: str):
    store = CVEStore(db_path)
    items = load_json_file(json_path)
    store.bulk_insert(items)
    print(f"Loaded {len(items)} CVEs into {db_path} from {json_path}")
    store.close()