import os
import json, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from awsas.cve.store import CVEStore
from awsas.cve.matcher import match_components_to_cves

TEST_DB = "test_cve.db"


def make_test_db():
    # wyczyść poprzednią testową bazę
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

    store = CVEStore(TEST_DB)

    # 1) CVE podatne na jQuery <= 3.6.0
    cve_jquery_range = {
        "cve": {
            "CVE_data_meta": {"ID": "CVE-2024-0001"},
            "description": {
                "description_data": [
                    {
                        "lang": "en",
                        "value": "XSS vulnerability in jQuery through 3.6.0."
                    }
                ]
            },
        },
        "configurations": {
            "nodes": [
                {
                    "cpe_match": [
                        {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
                            "versionEndIncluding": "3.6.0",
                        }
                    ]
                }
            ]
        },
    }

    # 2) CVE podatne na jQuery <= 3.5.0 (dla sprawdzenia not_vulnerable)
    cve_jquery_old = {
        "cve": {
            "CVE_data_meta": {"ID": "CVE-2023-0002"},
            "description": {
                "description_data": [
                    {
                        "lang": "en",
                        "value": "Some issue in jQuery up to 3.5.0."
                    }
                ]
            },
        },
        "configurations": {
            "nodes": [
                {
                    "cpe_match": [
                        {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
                            "versionEndIncluding": "3.5.0",
                        }
                    ]
                }
            ]
        },
    }

    # 3) CVE na Django, żeby sprawdzić czy nie wpada przy jQuery
    cve_django = {
        "cve": {
            "CVE_data_meta": {"ID": "CVE-2024-9999"},
            "description": {
                "description_data": [
                    {
                        "lang": "en",
                        "value": "SQL injection in Django 4.2.x"
                    }
                ]
            },
        },
        "configurations": {
            "nodes": [
                {
                    "cpe_match": [
                        {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:django:django:4.2.0:*:*:*:*:*:*:*",
                        }
                    ]
                }
            ]
        },
    }

    store.bulk_insert([cve_jquery_range, cve_jquery_old, cve_django])
    store.close()


def run_test():
    make_test_db()

    # Symulujemy fingerprint:
    components = [
        {"name": "jQuery", "version": "3.6.0"},
        {"name": "jQuery", "version": "2.2.1"},
        {"name": "jQuery", "version": "3.5.0"},
        {"name": "Django", "version": "4.2.0"},
    ]

    results = match_components_to_cves(
        components=components,
        db_path=TEST_DB,
        limit_per_component=10,
    )

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    run_test()