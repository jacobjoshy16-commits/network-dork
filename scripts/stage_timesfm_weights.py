#!/usr/bin/env python3
"""Stage TimesFM weights for an offline or air-gapped deployment.

Run this once on a connected host, verify the manifest, then move the
directory to the target environment. The sidecar runs with HF_HUB_OFFLINE=1
and never downloads anything itself.

Only TimesFM 2.5 and earlier are Apache-2.0. The 3.0 weights are released
under a non-commercial licence that forbids production use, so this script
refuses to stage them.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys

APACHE_CHECKPOINTS = {
    "google/timesfm-2.5-200m-pytorch",
    "google/timesfm-2.0-500m-pytorch",
    "google/timesfm-1.0-200m-pytorch",
}
NON_COMMERCIAL = re.compile(r"timesfm[-_]?3(\.|$|[-_])", re.IGNORECASE)


def write_manifest(directory: Path) -> Path:
    """Record a digest per file so the transfer can be verified offline."""
    entries = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.relative_to(directory)}")
    manifest = directory / "SHA256SUMS"
    manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint",
        default="google/timesfm-2.5-200m-pytorch",
        help="HuggingFace repository id of an Apache-2.0 TimesFM checkpoint.",
    )
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument(
        "--allow-unlisted",
        action="store_true",
        help="Permit a checkpoint that is not in the known Apache-2.0 set.",
    )
    args = parser.parse_args()

    if NON_COMMERCIAL.search(args.checkpoint):
        print(
            f"Refusing {args.checkpoint!r}: TimesFM 3.x weights are licensed "
            "for non-commercial, non-production use. Use 2.5.",
            file=sys.stderr,
        )
        return 2
    if args.checkpoint not in APACHE_CHECKPOINTS and not args.allow_unlisted:
        print(
            f"{args.checkpoint!r} is not a known Apache-2.0 checkpoint. "
            "Confirm its licence, then pass --allow-unlisted.",
            file=sys.stderr,
        )
        return 2

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print(
            "huggingface_hub is required to stage weights: "
            "pip install huggingface_hub",
            file=sys.stderr,
        )
        return 1

    args.destination.mkdir(parents=True, exist_ok=True)
    snapshot_download(
        repo_id=args.checkpoint,
        local_dir=str(args.destination),
    )
    manifest = write_manifest(args.destination)
    print(f"Staged {args.checkpoint} into {args.destination}")
    print(f"Manifest: {manifest}")
    print(
        "Transfer the directory to the target host and mount it at "
        "/models/timesfm-2.5-200m in the sidecar container."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
