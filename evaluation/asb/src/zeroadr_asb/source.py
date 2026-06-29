from __future__ import annotations

from pathlib import Path
import subprocess

from zeroadr_asb.manifest import ASB_COMMIT


class ASBSourceError(RuntimeError):
    code = "asb_source_error"


def prepare_asb_source(asb_root: Path, commit: str = ASB_COMMIT) -> dict[str, str]:
    if commit != ASB_COMMIT:
        raise ASBSourceError(f"Unsupported ASB commit; expected {ASB_COMMIT}.")
    if not asb_root.exists():
        asb_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        result = subprocess.run(
            ["git", "clone", "https://github.com/agiresearch/ASB.git", str(asb_root)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise ASBSourceError("Unable to clone the official ASB repository.")
    checkout = subprocess.run(
        ["git", "-C", str(asb_root), "checkout", "--detach", commit],
        capture_output=True,
        text=True,
        check=False,
    )
    if checkout.returncode != 0:
        raise ASBSourceError("Unable to check out the pinned ASB commit.")
    verify_asb_source(asb_root, commit)
    return {"asb_root": str(asb_root), "commit": commit}


def verify_asb_source(asb_root: Path, commit: str = ASB_COMMIT) -> None:
    result = subprocess.run(
        ["git", "-C", str(asb_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != commit:
        raise ASBSourceError("ASB source is missing or does not match the pinned commit.")
