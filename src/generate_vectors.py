"""Deterministic generator for HAWK weak-key BUFF counterexamples.

Produces test vectors in two formats (NIST PQC `.rsp` KAT and JSON) for three
families of malformed-public-key attacks against HAWK Round 2:

    1. MBS    -- one malformed pk + one signature, two distinct messages, both verify.
    2. M-S-UEO -- one message + one signature, multiple distinct malformed pks, all verify.
    3. wNR    -- one malformed pk + one signature, many high-entropy messages, all verify.

The script uses ONLY the official HAWK Round 2 Python reference (`Extra/hawk-py/codec.py`)
for byte encoding. It does not import any verifier; verification is performed by the
two independent drivers in `drivers/`.

Run as a module to keep `Extra/hawk-py/` on the import path:

    python3 -m src.generate_vectors --out-dir vectors

Determinism: every byte produced is a pure function of the recipe constants below.
There is no DRBG, no salt sampling, no randomness anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
HAWK_PY = ROOT / "third_party" / "hawk-sign-submission" / "hawk-submission" / "Extra" / "hawk-py"
sys.path.insert(0, str(HAWK_PY))

from codec import encode_public, encode_sign  # noqa: E402  official HAWK encoder
from params import PARAMS  # noqa: E402  official HAWK parameter table


PARAM_SETS = [
    ("Hawk-256", 8),
    ("Hawk-512", 9),
    ("Hawk-1024", 10),
]

MBS_MSG_0 = b"HAWK malformed-key MBS counterexample message 0"
MBS_MSG_1 = b"HAWK malformed-key MBS counterexample message 1"
M_S_UEO_MSG = b"HAWK malformed-key M-S-UEO counterexample message"
M_S_UEO_Q01_VALUES = [0, 1, 2, 16]
WNR_MSG_PREFIX = b"hawk-weak-keys wNR challenge "
WNR_TRIALS_PER_SET = {8: 100, 9: 100, 10: 100}


def make_constant_pk_bytes(logn: int, q00_const: int, q01_const: int) -> bytes:
    """Encode the malformed public key (constant q00, constant q01)."""
    n = 1 << logn
    q00 = np.zeros(n, dtype=np.int16)
    q01 = np.zeros(n, dtype=np.int16)
    q00[0] = q00_const
    q01[0] = q01_const
    pk = encode_public(logn, q00, q01)
    if pk is None:
        raise RuntimeError(f"encode_public failed for logn={logn} q00={q00_const} q01={q01_const}")
    return bytes(pk.tolist())


def make_zero_sig_bytes(logn: int) -> bytes:
    """Encode the all-zero signature: salt = 0, s1 = 0."""
    n = 1 << logn
    salt = np.zeros(PARAMS(logn, "lensalt"), dtype=np.uint8)
    s1 = np.zeros(n, dtype=np.int16)
    sig = encode_sign(logn, salt, s1)
    if sig is None:
        raise RuntimeError(f"encode_sign failed for logn={logn}")
    return bytes(sig.tolist())


def shake256(data: bytes, length: int) -> bytes:
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(length)


def wnr_message(index: int) -> bytes:
    """SHAKE-derived 32-byte hidden challenge message keyed by trial index."""
    return shake256(WNR_MSG_PREFIX + index.to_bytes(8, "little"), 32)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shake256_32_hex(data: bytes) -> str:
    return shake256(data, 32).hex()


def write_rsp(path: Path, alg_name: str, header_comment: str, records: list[dict]) -> None:
    """Write a NIST PQC `.rsp` KAT file with weak-key vectors.

    Each record carries:
      count, seed (placeholder), mlen, msg, pk, sk (placeholder), smlen, sm
    where `sm = msg || sig` per the standard `crypto_sign` convention.

    Reviewers' parsers can ingest these unchanged. The seed/sk fields are placeholders
    because malformed keys do not come from honest keygen.
    """
    lines: list[str] = []
    lines.append(f"# {alg_name}")
    for line in header_comment.splitlines():
        lines.append(f"# {line}")
    lines.append("")
    for rec in records:
        lines.append(f"count = {rec['count']}")
        lines.append(f"seed = {rec['seed_hex'].upper()}")
        lines.append(f"mlen = {rec['mlen']}")
        lines.append(f"msg = {rec['msg_hex'].upper()}")
        lines.append(f"pk = {rec['pk_hex'].upper()}")
        lines.append(f"sk = {rec['sk_hex'].upper()}")
        lines.append(f"smlen = {rec['smlen']}")
        lines.append(f"sm = {rec['sm_hex'].upper()}")
        lines.append("")
    path.write_text("\n".join(lines))


def make_record(count: int, msg: bytes, pk: bytes, sig: bytes, lenpriv: int) -> dict:
    sm = msg + sig
    return {
        "count": count,
        "seed_hex": "00" * 48,                # placeholder; not used by verification
        "mlen": len(msg),
        "msg_hex": msg.hex(),
        "pk_hex": pk.hex(),
        "sk_hex": "00" * lenpriv,             # placeholder; not used by verification
        "smlen": len(sm),
        "sm_hex": sm.hex(),
    }


def generate_mbs(alg_name: str, logn: int, out_json: Path, out_rsp: Path) -> dict:
    pk = make_constant_pk_bytes(logn, 1, 1)
    sig = make_zero_sig_bytes(logn)
    lenpriv = PARAMS(logn, "lenpriv")
    msgs = [MBS_MSG_0, MBS_MSG_1]

    records_rsp = [make_record(i, m, pk, sig, lenpriv) for i, m in enumerate(msgs)]
    header = (
        "Weak-key MBS counterexample.\n"
        "Recipe: q00 = constant polynomial 1, q01 = constant polynomial 1,\n"
        "        salt = all zeros, s1 = constant polynomial 0.\n"
        "Same encoded malformed (pk, sig) verifies for two distinct messages.\n"
        "Falsifies MBS (Aulbach-Duzlu-Meyer-Struck-Weishaupl 2024/591) over verifier-accepted\n"
        "byte-decodable public keys.  WARNING: pk is malformed; not from honest keygen."
    )
    write_rsp(out_rsp, alg_name, header, records_rsp)

    json_obj = {
        "claim": "MBS",
        "parameter_set": alg_name,
        "logn": logn,
        "recipe": {
            "q00": "constant polynomial 1",
            "q01": "constant polynomial 1",
            "salt": "all-zero (lensalt bytes)",
            "s1": "constant polynomial 0",
        },
        "shared": {
            "pk_hex": pk.hex(),
            "pk_sha256": sha256_hex(pk),
            "pk_shake256_32": shake256_32_hex(pk),
            "sig_hex": sig.hex(),
            "sig_sha256": sha256_hex(sig),
            "sig_shake256_32": shake256_32_hex(sig),
        },
        "records": [
            {"index": i, "msg_hex": m.hex(), "msg_ascii_hint": m.decode(errors="replace"),
             "expected_accept": True} for i, m in enumerate(msgs)
        ],
        "rsp_file": out_rsp.name,
        "note": "Same (pk, sig) accepts both messages.  Falsifies MBS.",
    }
    out_json.write_text(json.dumps(json_obj, indent=2) + "\n")
    return json_obj


def generate_m_s_ueo(alg_name: str, logn: int, out_json: Path, out_rsp: Path) -> dict:
    sig = make_zero_sig_bytes(logn)
    lenpriv = PARAMS(logn, "lenpriv")
    msg = M_S_UEO_MSG

    records_rsp = []
    pk_records = []
    for i, q01_const in enumerate(M_S_UEO_Q01_VALUES):
        pk = make_constant_pk_bytes(logn, 1, q01_const)
        records_rsp.append(make_record(i, msg, pk, sig, lenpriv))
        pk_records.append({
            "index": i,
            "q01_constant": q01_const,
            "pk_hex": pk.hex(),
            "pk_sha256": sha256_hex(pk),
            "pk_shake256_32": shake256_32_hex(pk),
            "expected_accept": True,
        })

    header = (
        "Weak-key M-S-UEO counterexample.\n"
        "Recipe: q00 = constant polynomial 1, q01 = constant polynomial a for a in {0, 1, 2, 16},\n"
        "        salt = all zeros, s1 = constant polynomial 0, message fixed.\n"
        "Same encoded (msg, sig) verifies under multiple distinct malformed public keys.\n"
        "Falsifies M-S-UEO (malicious-strong-universal-exclusive-ownership) over malformed pks.\n"
        "WARNING: each pk is malformed; not from honest keygen."
    )
    write_rsp(out_rsp, alg_name, header, records_rsp)

    json_obj = {
        "claim": "M-S-UEO",
        "parameter_set": alg_name,
        "logn": logn,
        "recipe": {
            "q00": "constant polynomial 1",
            "q01": f"constant polynomial a for a in {M_S_UEO_Q01_VALUES}",
            "salt": "all-zero",
            "s1": "constant polynomial 0",
            "msg": "fixed ASCII string",
        },
        "shared": {
            "msg_hex": msg.hex(),
            "msg_ascii_hint": msg.decode(errors="replace"),
            "sig_hex": sig.hex(),
            "sig_sha256": sha256_hex(sig),
            "sig_shake256_32": shake256_32_hex(sig),
        },
        "records": pk_records,
        "rsp_file": out_rsp.name,
        "note": "Same (msg, sig) accepts under all four distinct malformed pks.  Falsifies M-S-UEO.",
    }
    out_json.write_text(json.dumps(json_obj, indent=2) + "\n")
    return json_obj


def generate_wnr(alg_name: str, logn: int, trials: int, out_json: Path, out_rsp: Path) -> dict:
    pk = make_constant_pk_bytes(logn, 1, 1)
    sig = make_zero_sig_bytes(logn)
    lenpriv = PARAMS(logn, "lenpriv")

    msgs = [wnr_message(i) for i in range(trials)]
    records_rsp = [make_record(i, m, pk, sig, lenpriv) for i, m in enumerate(msgs)]

    header = (
        f"Weak-key wNR (weak non-resignability) attack shape, {trials} hidden messages.\n"
        "Recipe: q00 = constant polynomial 1, q01 = constant polynomial 1,\n"
        "        salt = all zeros, s1 = constant polynomial 0.\n"
        "Each msg is SHAKE256(\"hawk-weak-keys wNR challenge \" || trial_le8)[0..32].\n"
        "All records expected to accept under the fixed malformed (pk, sig).\n"
        "WARNING: pk is malformed; not from honest keygen."
    )
    write_rsp(out_rsp, alg_name, header, records_rsp)

    json_obj = {
        "claim": "wNR",
        "parameter_set": alg_name,
        "logn": logn,
        "trials": trials,
        "recipe": {
            "q00": "constant polynomial 1",
            "q01": "constant polynomial 1",
            "salt": "all-zero",
            "s1": "constant polynomial 0",
            "msg_i": "SHAKE256('hawk-weak-keys wNR challenge ' || i.to_bytes(8, 'little'))[0..32]",
        },
        "shared": {
            "pk_hex": pk.hex(),
            "pk_sha256": sha256_hex(pk),
            "pk_shake256_32": shake256_32_hex(pk),
            "sig_hex": sig.hex(),
            "sig_sha256": sha256_hex(sig),
            "sig_shake256_32": shake256_32_hex(sig),
        },
        "first_three_msgs": [
            {"index": i, "msg_hex": msgs[i].hex()} for i in range(min(3, trials))
        ],
        "rsp_file": out_rsp.name,
        "note": (
            "Verifier should accept all records.  100% acceptance falsifies wNR's hiding "
            "premise: the adversary commits to a fixed (pk, sig) that opens to every challenge "
            "message (Aulbach et al. 2024/591 wNR game)."
        ),
    }
    out_json.write_text(json.dumps(json_obj, indent=2) + "\n")
    return json_obj


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default=str(ROOT / "vectors"))
    parser.add_argument("--wnr-trials-256", type=int, default=WNR_TRIALS_PER_SET[8])
    parser.add_argument("--wnr-trials-512", type=int, default=WNR_TRIALS_PER_SET[9])
    parser.add_argument("--wnr-trials-1024", type=int, default=WNR_TRIALS_PER_SET[10])
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    json_dir = out_dir / "json"
    rsp_dir = out_dir / "kat"
    json_dir.mkdir(parents=True, exist_ok=True)
    rsp_dir.mkdir(parents=True, exist_ok=True)

    wnr_trials = {8: args.wnr_trials_256, 9: args.wnr_trials_512, 10: args.wnr_trials_1024}

    summary = []
    for alg_name, logn in PARAM_SETS:
        suffix = {8: "256", 9: "512", 10: "1024"}[logn]
        mbs = generate_mbs(alg_name, logn,
                           json_dir / f"mbs_hawk{suffix}.json",
                           rsp_dir / f"mbs_hawk{suffix}.rsp")
        useo = generate_m_s_ueo(alg_name, logn,
                                json_dir / f"m_s_ueo_hawk{suffix}.json",
                                rsp_dir / f"m_s_ueo_hawk{suffix}.rsp")
        wnr = generate_wnr(alg_name, logn, wnr_trials[logn],
                           json_dir / f"wnr_hawk{suffix}.json",
                           rsp_dir / f"wnr_hawk{suffix}.rsp")
        summary.append({"alg": alg_name, "logn": logn, "mbs": len(mbs["records"]),
                        "m_s_ueo": len(useo["records"]), "wnr": wnr["trials"]})

    print(json.dumps({"generated": summary, "out_dir": str(out_dir)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
