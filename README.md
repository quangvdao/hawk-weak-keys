# HAWK Weak-Key Counterexamples: Reproducibility Artifact

This artifact provides byte-decodable test vectors that falsify three BUFF
properties of HAWK Round 2 over the verifier-accepted public-key domain.  Each vector is verified by **two independent
implementations**: the unmodified vendored HAWK Round 2 C reference and
the unmodified vendored HAWK Round 2 Python reference (`hawk-py`),
both shipped by the HAWK authors at <https://hawk-sign.info/submission.zip>.

The artifact is fully self-contained.  It contains no novel verifier code:
all verification is performed by the HAWK authors' own published
implementations.  Encoding is performed by the HAWK authors' own
`Extra/hawk-py/codec.py` only.

This artifact is the companion to the paper
*Weak Keys Break the BUFF Security of HAWK*, which contains the proof
analysis, candidate verifier-side checks (`KeyNormCheck`, `KeyShapeCheck`),
and the positive theorems.
The paper's §Proof Status and Open Problems states what is proved and what
remains open, including the gap between real-valued theorems and the
shipped fixed-point verifier.
This repository ships only the empirical witnesses against
the unmodified verifier; see `CLAIMS.md` for how the witnesses map to
the paper's claims.

## Summary

For every `(parameter set, claim)` pair, every record in the corresponding
`vectors/kat/*.rsp` file accepts under both verifiers:

| claim     | parameter sets         | what is shown |
|-----------|------------------------|---------------|
| MBS       | Hawk-256, 512, 1024    | one malformed `(pk, sig)` accepts two distinct messages |
| M-S-UEO   | Hawk-256, 512, 1024    | one `(msg, sig)` accepts under four distinct malformed pks |
| wNR       | Hawk-256, 512, 1024    | one fixed malformed `(pk, sig)` accepts every SHAKE-derived hidden message in 100/100 trials |

See `CLAIMS.md` for the precise BUFF-game framing, what is and is not broken,
and the literature anchors.

## Reproduction

The recommended path is the pinned Docker image:

```bash
cd hawk-weak-keys
docker build -t hawk-weak-keys -f docker/Dockerfile .
docker run --rm hawk-weak-keys
```

This runs `docker/reproduce.sh`, which:

1. Re-derives every test vector from its deterministic recipe via `src/generate_vectors.py`.
2. Diffs the regenerated vectors against the shipped `vectors/SHA256SUMS` manifest (byte-identical).
3. Builds and runs the C verifier on every `.rsp` file and confirms all-accept (full 318 records).
4. Runs the Python verifier on every MBS / M-S-UEO record (full, 18) and a 5-record sample of each wNR file (15 of 300).  Set `HAWK_WNR_FULL=1` to force a full Python check on all 300 wNR records.
5. Prints `ARTIFACT REPRODUCIBLE` iff every step passed.

End-to-end runtime on a recent laptop: ~1m30s with the default sampled
Python wNR check, ~30-60 minutes with `HAWK_WNR_FULL=1`.  The C-reference
side always covers every record on every set.

Without Docker (requires `python3 >= 3.10`, `gcc`, `make`, `numpy`, `sympy`):

```bash
pip install numpy sympy
python3 -m src.generate_vectors                       # regenerate vectors
( cd vectors && shasum -a 256 -c SHA256SUMS )         # confirm byte-identical
( cd drivers && make )                                # build C verifier (~2s)
drivers/verify_kat vectors/kat/*.rsp                  # all PASS (full 318 records)
python3 drivers/verify_kat.py vectors/kat/mbs_hawk*.rsp vectors/kat/m_s_ueo_hawk*.rsp
python3 drivers/verify_kat.py --max-records 5 vectors/kat/wnr_hawk*.rsp
```

## Repository layout

```
hawk-weak-keys/
├── README.md                       you are here
├── CLAIMS.md                       precise BUFF claims, definitions, scope
├── docker/
│   ├── Dockerfile                  pinned ubuntu:22.04 + gcc + python3 + numpy/sympy
│   └── reproduce.sh                end-to-end reproduction script
├── src/
│   └── generate_vectors.py         deterministic generator (uses official codec.py)
├── drivers/
│   ├── verify_kat.c                standalone C verifier (uses vendored hawk_verify_finish)
│   ├── verify_kat.py               standalone Python verifier (uses vendored hawk-py)
│   └── Makefile                    builds the C verifier
├── vectors/
│   ├── json/                       human-readable test vectors with hashes
│   ├── kat/                        NIST PQC `.rsp` test vectors (loadable by any HAWK tool)
│   └── SHA256SUMS                  tamper-evident manifest of every vector file
└── third_party/
    ├── README.md                   vendoring provenance, licensing, integrity
    ├── submission.zip              bit-identical original archive (kept for integrity)
    └── hawk-sign-submission/       extracted HAWK Round 2 NIST submission (unmodified)
```

## Provenance

The vendored HAWK Round 2 submission was downloaded from the official URL:

```
URL:           https://hawk-sign.info/submission.zip
last-modified: Wed, 21 May 2025 09:11:44 GMT
content-length: 6111768
SHA256:        301ebfd625877a9997bad6441bc9d69b01df5f6aba35332caa113f6462a96f86
```

`third_party/submission.zip` is the bit-identical archive.  Reviewers can
re-download from the official URL and confirm the SHA256 matches.

The HAWK specification itself is at:
<https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/spec-files/hawk-spec-round2-web.pdf>
(HAWK v1.1, dated 2025-02-05).

## Test-vector formats

Both formats describe the same witnesses; pick whichever suits your tooling.

### NIST KAT: `vectors/kat/*.rsp`

Standard format with `count`, `seed` (placeholder), `mlen`, `msg`, `pk`,
`sk` (placeholder), `smlen`, `sm` per record, where `sm = msg || sig`
matches the HAWK NIST API `crypto_sign` convention.  `seed` and `sk` are
placeholders because malformed keys do not come from honest keygen; only
`pk`, `msg`, and `sm` are required for verification.

Any HAWK verifier (existing test harnesses, future implementations, AVX2
optimised builds, etc.) can ingest these files unchanged.

### JSON: `vectors/json/*.json`

JSON schema:

```json
{
  "claim": "MBS" | "M-S-UEO" | "wNR",
  "parameter_set": "Hawk-{256,512,1024}",
  "logn": 8 | 9 | 10,
  "recipe": { ...deterministic recipe constants... },
  "shared": { "pk_hex": "...", "sig_hex": "...", "pk_sha256": "...", ... },
  "records": [ ...per-record `(msg, expected_accept)`... ],
  "rsp_file": "...corresponding .rsp filename...",
  "note": "..."
}
```

The JSON is a strict superset of the `.rsp` content (it adds SHA-256
and SHAKE256-32 digests of the encoded `pk` and `sig`, plus ASCII hints
for human-readable messages).

## Determinism and integrity

Every byte produced by `src/generate_vectors.py` is a pure function of:

- the recipe constants (constant `q00`, constant `q01`, all-zero salt, zero `s1`),
- the shipped HAWK `Extra/hawk-py/codec.py` (unmodified),
- ASCII / SHAKE-derived messages with documented preimages.

There is no DRBG, no salt sampling, no randomness in the artifact.  Re-running
`src/generate_vectors.py` produces byte-identical output across machines.

`vectors/SHA256SUMS` records the SHA-256 of every shipped vector file.  Any
deviation means either:

1. the vendored `codec.py` changed (which the SHA256 of `submission.zip`
   would also flag), or
2. the recipe constants in `src/generate_vectors.py` changed.

In either case, the artifact's `docker/reproduce.sh` would refuse to print
`ARTIFACT REPRODUCIBLE`.

## What is and is not claimed

See `CLAIMS.md` for the precise statement, including a line-by-line
account of which steps in the BUFF analysis the witnesses trip.  In one
sentence: this artifact shows that the HAWK Round 2 verifier accepts
byte-decodable public keys for which the BUFF analysis of
Aulbach-Düzlü-Meyer-Struck-Weishäupl 2024/591 §5.1 has at least four
specific holes, one structural (the factor `(q01/q00)·f − F` in the
MBS coordinate decomposition can be *exactly zero*, which it is for
the natural algebraic preimage `(1, 0, 1, 1)` of these keys) and three
quantitative (no magnitude bound on the proof's "fixed values"; the
S-CEO θ-ball volume estimate reused for M-S-UEO and wNR is derived for
honest-scale `(q00, q01)` only; the implicit existential quantifier
over algebraic preimages is not restricted to honest-norm preimages).
The same θ-ball estimate and implicit existential underpin the S-CEO
and S-DEO proofs in §5.1, so all four BUFF proofs of HAWK in §5.1 are
structurally unsound on the verifier-accepted public-key domain; this
artifact ships empirical counterexamples for MBS, M-S-UEO, and wNR,
and does not exhibit witnesses against the S-CEO or S-DEO games for
this specific weak-key family.  The witnesses fall *inside* the
proof's algebraic domain (each pk has a valid NTRU preimage with
`f·G − g·F = 1`); they are not "outside the proof's assumed key class".

This artifact does **not** falsify HAWK SUF-CMA on honestly generated
keys, and does **not** ship S-CEO / S-DEO witnesses with honest
signature reuse on this weak-key family.

The MBS result also closes a route in the downstream paper Düzlü-Struck
2024/1669, which generically reduces S-UEO and wNR of PS-3-transformed
schemes to MBS of the underlying scheme: HAWK is a PS-3-transformed
scheme in that paper's sense, and 2024/1669's narrative that "MBS rules
out effective weak keys" lifts ADMSW24's HAWK ✓ as the canonical
lattice case.  The malformed `(pk, sig)` shipped here is exactly the
kind of effective weak key that narrative says MBS forbids.  See the
*Cascade* section of `CLAIMS.md`.

## License

The artifact's own files (everything outside `third_party/`) are released
under the MIT License; see `LICENSE` at the repository root.

The contents of `third_party/hawk-sign-submission/` and
`third_party/submission.zip` are the unmodified HAWK Round 2 NIST PQC
submission and remain under their original licenses (see
`third_party/hawk-sign-submission/hawk-submission/Extra/hawk-py/LICENSE.txt`
for the Python reference's MIT license).
