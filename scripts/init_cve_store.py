from __future__ import annotations

import argparse
import gzip
import hashlib
import shutil
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from awsas.cve.sync import sync_from_file

NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"


def _http_get(url: str, timeout: int = 120) -> bytes:
    req = Request(url, headers={"User-Agent": "awsas-init-cve-store/1.0"})
    with urlopen(req, timeout=timeout) as r:
        return r.read()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_expected_sha256(sha256_text: str) -> Optional[str]:
    parts = sha256_text.strip().split()
    if not parts:
        return None
    h = parts[0].strip().lower()
    if len(h) >= 64:
        return h[:64]
    return None


def _download_feed_file(filename: str, out_dir: Path, verify: bool = True) -> Optional[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    gz_url = f"{NVD_BASE}/{filename}"
    sha_url = f"{gz_url}.sha256"

    gz_path = out_dir / filename
    sha_path = out_dir / f"{filename}.sha256"

    print(f"[+] Download: {gz_url}")
    try:
        gz_bytes = _http_get(gz_url)
    except HTTPError as e:
        if e.code == 404:
            print(f"[!] 404 Not Found: {gz_url} -> skipping")
            return None
        raise
    except URLError as e:
        raise RuntimeError(f"Network error downloading {gz_url}: {e}") from e

    gz_path.write_bytes(gz_bytes)

    if verify:
        print(f"[+] Download: {sha_url}")
        try:
            sha_text = _http_get(sha_url).decode("utf-8", errors="ignore")
            sha_path.write_text(sha_text, encoding="utf-8")
            expected = _parse_expected_sha256(sha_text)
            if not expected:
                raise RuntimeError(f"Could not parse sha256 for {filename}")

            actual = _sha256_bytes(gz_bytes).lower()
            if actual != expected.lower():
                raise RuntimeError(
                    f"SHA256 mismatch for {filename}\nexpected={expected}\nactual={actual}"
                )
            print(f"[+] SHA256 OK: {filename}")
        except HTTPError:
            print(f"[!] SHA256 not available for {filename} -> skipping verify for this file")

    return gz_path


def _gunzip_to_json(gz_path: Path, json_path: Path) -> None:
    print(f"[+] Extract: {gz_path.name} -> {json_path.name}")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(gz_path, "rb") as fin, json_path.open("wb") as fout:
        shutil.copyfileobj(fin, fout)


def _years_from_args(years: Optional[str], since: Optional[int]) -> list[int]:
    this_year = time.gmtime().tm_year

    if years:
        out: list[int] = []
        for part in years.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                out.extend(list(range(int(a), int(b) + 1)))
            else:
                out.append(int(part))
        out = sorted(set(out))
        return out

    if since is not None:
        return list(range(int(since), this_year + 1))

    return list(range(2002, this_year + 1))


def main() -> int:
    p = argparse.ArgumentParser(description="Download NVD CVE 2.0 feeds and build cve_store.db")
    p.add_argument("--db", default=str(PROJECT_ROOT / "data" / "cve_store.db"), help="Output sqlite db path")
    p.add_argument("--data-dir", default=str(PROJECT_ROOT / "data"), help="Directory for downloaded feeds")
    p.add_argument("--years", default=None, help="Comma list or ranges, e.g. 2022-2025,2019")
    p.add_argument("--since", type=int, default=None, help="Shortcut: build from YEAR..current")
    p.add_argument("--no-verify", action="store_true", help="Disable sha256 verification")
    p.add_argument("--keep-json", action="store_true", help="Keep extracted .json files")
    p.add_argument("--with-recent", action="store_true", help="Include NVD recent feed (nvdcve-2.0-recent.json.gz)")
    p.add_argument("--with-modified", action="store_true", help="Include NVD modified feed (nvdcve-2.0-modified.json.gz)")
    args = p.parse_args()

    db_path = Path(args.db).resolve()
    data_dir = Path(args.data_dir).resolve()
    feeds_dir = data_dir / "nvd_feeds"
    extracted_dir = data_dir / "nvd_extracted"
    feeds_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir.mkdir(parents=True, exist_ok=True)

    years = _years_from_args(args.years, args.since)
    verify = not args.no_verify

    db_path.parent.mkdir(parents=True, exist_ok=True)

    print("[i] Project root:", PROJECT_ROOT)
    print("[i] DB path:", db_path)
    print("[i] Years:", years)
    print("[i] Verify SHA256:", verify)

    start = time.time()

    for y in years:
        fname = f"nvdcve-2.0-{y}.json.gz"
        gz_path = _download_feed_file(fname, feeds_dir, verify=verify)
        if gz_path is None:
            continue

        json_path = extracted_dir / f"nvdcve-2.0-{y}.json"
        _gunzip_to_json(gz_path, json_path)

        print(f"[+] Syncing year {y} into DB...")
        sync_from_file(str(db_path), str(json_path))

        if not args.keep_json:
            json_path.unlink(missing_ok=True)

    if args.with_recent:
        print("[+] Processing NVD recent feed")
        fname = "nvdcve-2.0-recent.json.gz"
        gz_path = _download_feed_file(fname, feeds_dir, verify=verify)
        if gz_path is not None:
            json_path = extracted_dir / "nvdcve-2.0-recent.json"
            _gunzip_to_json(gz_path, json_path)
            sync_from_file(str(db_path), str(json_path))
            if not args.keep_json:
                json_path.unlink(missing_ok=True)

    if args.with_modified:
        print("[+] Processing NVD modified feed")
        fname = "nvdcve-2.0-modified.json.gz"
        gz_path = _download_feed_file(fname, feeds_dir, verify=verify)
        if gz_path is not None:
            json_path = extracted_dir / "nvdcve-2.0-modified.json"
            _gunzip_to_json(gz_path, json_path)
            sync_from_file(str(db_path), str(json_path))
            if not args.keep_json:
                json_path.unlink(missing_ok=True)

    print(f"[+] Done. Total time: {time.time() - start:.1f}s")
    print(f"[+] DB ready: {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())