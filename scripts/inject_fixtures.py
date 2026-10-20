"""Inject Wazuh fixtures into the alerts table via the ingestion pipeline.

Usage:
    python scripts/inject_fixtures.py --tenant-id org_aa [--fixtures-dir PATH]

Reads every *.json fixture from adapters/siem/wazuh/fixtures/, strips the
test-only `_fixture` block, parses via the Wazuh adapter, and ingests.

Decision #6 semantics apply: re-running this script will not create
duplicate rows for content-identical alerts, but will fail loudly
(AlertConflictError) if the same canonical_id appears with different
content — which should not happen with the checked-in fixtures.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from adapters.siem.wazuh.src import parse as wazuh_parse
from core.ingestion.ingest import ingest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument(
        "--fixtures-dir",
        default=str(REPO_ROOT / "adapters" / "siem" / "wazuh" / "fixtures"),
    )
    args = parser.parse_args()

    fixture_paths = sorted(Path(args.fixtures_dir).glob("*.json"))
    if not fixture_paths:
        print(f"No fixtures found in {args.fixtures_dir}", file=sys.stderr)
        return 1

    inserted = skipped = errors = 0
    for path in fixture_paths:
        try:
            with open(path) as f:
                raw = json.load(f)
            raw.pop("_fixture", None)

            alert_dict = wazuh_parse(raw, tenant_id=args.tenant_id)
            alert_id = ingest(alert_dict, tenant_id=args.tenant_id)
            print(f"  ✓ {path.name} -> {alert_id}")
            inserted += 1
        except Exception as exc:
            print(f"  ✗ {path.name}: {exc}", file=sys.stderr)
            errors += 1

    print(f"\nInserted: {inserted}  Errors: {errors}")
    return 0 if errors == 0 else 2


if __name__ == "__main__":
    sys.exit(main())