#!/usr/bin/env python3
"""Create read-only and write-scoped OpenSearch roles for network-dork.

This script configures the security plugin only. It does not modify telemetry
and it does not verify report content.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_dork.adapters.opensearch_security import (
    OpenSearchSecurityBootstrapper,
    SecurityBootstrapConfig,
    verify_read_credential_cannot_write,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--admin-username", required=True)
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--telemetry-user", required=True)
    parser.add_argument("--telemetry-password", required=True)
    parser.add_argument("--report-user", required=True)
    parser.add_argument("--report-password", required=True)
    parser.add_argument("--report-index", required=True)
    parser.add_argument(
        "--telemetry-index",
        action="append",
        dest="telemetry_indexes",
        required=True,
        help="Repeat for alerts, flow, DNS, and auth index patterns.",
    )
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bootstrapper = OpenSearchSecurityBootstrapper(
        base_url=args.base_url,
        admin_username=args.admin_username,
        admin_password=args.admin_password,
        timeout_seconds=args.timeout_seconds,
    )
    try:
        bootstrapper.bootstrap(
            SecurityBootstrapConfig(
                telemetry_user=args.telemetry_user,
                telemetry_password=args.telemetry_password,
                report_user=args.report_user,
                report_password=args.report_password,
                telemetry_indexes=args.telemetry_indexes,
                report_index=args.report_index,
            )
        )
    finally:
        bootstrapper.close()

    verify_read_credential_cannot_write(
        base_url=args.base_url,
        report_index=args.report_index,
        username=args.telemetry_user,
        password=args.telemetry_password,
        timeout_seconds=args.timeout_seconds,
    )
    print("OpenSearch roles, users, and mappings configured.")
    print("Verified: telemetry credential cannot write to the report index.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
