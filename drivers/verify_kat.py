"""Verify HAWK weak-key NIST PQC `.rsp` KAT files using the official Python reference.

Calls `verify.hawkverify` from the unmodified HAWK Round 2 submission's `Extra/hawk-py/`.
This is one of the two independent verifiers in this artifact (the other is the C reference
in `drivers/verify_kat.c`).

Usage:

    python3 drivers/verify_kat.py vectors/kat/mbs_hawk512.rsp [more.rsp ...]

Exits 0 iff every record verifies as `accept`.  Per the artifact's claims, every record
in every shipped `.rsp` should accept; a single reject is a regression.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
HAWK_PY = ROOT / "third_party" / "hawk-sign-submission" / "hawk-submission" / "Extra" / "hawk-py"
sys.path.insert(0, str(HAWK_PY))

from params import PARAMS  # noqa: E402  official parameter table
from verify import hawkverify  # noqa: E402  official Python verifier (unmodified)


PARAM_LEN_TO_LOGN = {
    PARAMS(8, "lenpub"): 8,
    PARAMS(9, "lenpub"): 9,
    PARAMS(10, "lenpub"): 10,
}


@dataclass
class Record:
    count: int
    msg: bytes
    pk: bytes
    sm: bytes


def parse_rsp(path: Path) -> tuple[str, list[Record]]:
    """Parse a NIST PQC `.rsp` file into (algorithm_name, records).

    The parser tolerates `# ...` comment lines anywhere; key=value lines are
    grouped into records by `count = N`.
    """
    alg_name = ""
    records: list[Record] = []
    current: dict[str, str] = {}

    with path.open() as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                if current:
                    records.append(_record_from_dict(current))
                    current = {}
                continue
            if line.startswith("#"):
                if not alg_name and len(line) > 1:
                    alg_name = line.lstrip("# ").strip()
                continue
            m = re.match(r"^([a-zA-Z_]+)\s*=\s*(.*)$", line)
            if not m:
                continue
            key, val = m.group(1), m.group(2)
            if key == "count" and current:
                records.append(_record_from_dict(current))
                current = {}
            current[key] = val

    if current:
        records.append(_record_from_dict(current))

    return alg_name, records


def _record_from_dict(d: dict[str, str]) -> Record:
    count = int(d["count"])
    msg = bytes.fromhex(d["msg"]) if d.get("msg") else b""
    pk = bytes.fromhex(d["pk"])
    sm = bytes.fromhex(d["sm"])
    return Record(count=count, msg=msg, pk=pk, sm=sm)


def verify_one(record: Record) -> tuple[bool, int]:
    """Return (accept, logn).  Raises on unrecognised public key length."""
    logn = PARAM_LEN_TO_LOGN.get(len(record.pk))
    if logn is None:
        raise ValueError(f"public key length {len(record.pk)} does not match any HAWK parameter set")
    sig_len = PARAMS(logn, "lensig")
    if len(record.sm) < sig_len:
        raise ValueError(f"sm length {len(record.sm)} < lensig {sig_len}")
    msg = record.sm[: len(record.sm) - sig_len]
    sig = record.sm[len(record.sm) - sig_len:]
    if msg != record.msg:
        raise ValueError("sm prefix does not match msg")

    pk_arr = np.frombuffer(record.pk, dtype=np.uint8)
    msg_arr = np.frombuffer(msg, dtype=np.uint8)
    sig_arr = np.frombuffer(sig, dtype=np.uint8)
    return bool(hawkverify(logn, pk_arr, msg_arr, sig_arr)), logn


def verify_file(path: Path, max_records: int | None = None) -> tuple[int, int, str, int]:
    """Return (accepts, checked, alg_name, total_in_file) for one `.rsp` file."""
    alg_name, records = parse_rsp(path)
    total_in_file = len(records)
    if max_records is not None:
        records = records[:max_records]
    accepts = 0
    for rec in records:
        ok, _logn = verify_one(rec)
        if ok:
            accepts += 1
        else:
            print(f"REJECT  {path.name}  count={rec.count}", file=sys.stderr)
    return accepts, len(records), alg_name, total_in_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", help=".rsp file(s) to verify")
    parser.add_argument("--max-records", type=int, default=None,
                        help="verify at most N records per file (default: all)")
    args = parser.parse_args()

    failures = 0
    for p in args.paths:
        path = Path(p)
        accepts, checked, alg, total = verify_file(path, args.max_records)
        status = "PASS" if accepts == checked else "FAIL"
        suffix = f"({checked}/{total} sampled)" if checked < total else ""
        print(f"[{status}] python-ref  {path.name:40s}  alg={alg:32s}  {accepts}/{checked} accept {suffix}")
        if accepts != checked:
            failures += 1
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
