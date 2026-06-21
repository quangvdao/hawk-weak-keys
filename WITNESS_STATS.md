# Witness statistics

Compact reference tying the shipped vectors to the companion paper.
All digests are SHA-256 of the encoded `pk` or `sig` bytes as stored in
`vectors/json/*.json`.  No vector regeneration is required to reproduce
these values.

## Record counts

| claim | records per set | sets | total |
|-------|-----------------|------|-------|
| MBS | 2 | 3 | 6 |
| M-S-UEO | 4 | 3 | 12 |
| wNR | 100 | 3 | 300 |
| **all KAT records** | | | **318** |

C reference verifier: all 318 records (`docker/reproduce.sh` step 3).
Python reference verifier: all MBS and M-S-UEO records (18); wNR sampled
by default (5 per set) unless `HAWK_WNR_FULL=1`.

## Canonical weak-key recipe

All witnesses share the same algebraic family unless noted for M-S-UEO:

- `q00 = 1` (constant polynomial)
- `q01 = 1` for MBS and wNR; `q01 ∈ {0, 1, 2, 16}` for M-S-UEO
- `salt = 0`, `s1 = 0`

MBS messages (ASCII):

- `HAWK malformed-key MBS counterexample message 0`
- `HAWK malformed-key MBS counterexample message 1`

wNR messages: `SHAKE256("hawk-weak-keys wNR challenge " || le_uint64(i))[0..32]`
for `i = 0..99`.

## MBS: shared `(pk, sig)` digests

| set | `pk_sha256` (prefix) | `sig_sha256` (prefix) | `‖w‖²_Q` per message (paper) | bound `⌊8nσ_verify²⌋` |
|-----|----------------------|-----------------------|------------------------------|------------------------|
| HAWK-256 | `ab203c63…` | (see JSON) | (see companion paper) | 2223 |
| HAWK-512 | `3d67e3d7…` | `f10d3698…` | **499**, **513** | 8317 |
| HAWK-1024 | `bd155013…` | (see JSON) | (see companion paper) | 20218 |

Full hex digests: `vectors/json/mbs_hawk{256,512,1024}.json`.

## M-S-UEO: four distinct public keys per set

Each set uses one `(msg, sig)` and four malformed public keys with
`q00 = 1`, `q01 ∈ {0, 1, 2, 16}`.

| set | `q01` | `pk_sha256` (prefix) |
|-----|-------|----------------------|
| HAWK-256 | 0 | `0e7150cd…` |
| HAWK-256 | 1 | `ab203c63…` |
| HAWK-256 | 2 | `24b0f4c1…` |
| HAWK-256 | 16 | `6d453f8a…` |
| HAWK-512 | 0 | `c5e09be7…` |
| HAWK-512 | 1 | `3d67e3d7…` |
| HAWK-512 | 2 | `e5226223…` |
| HAWK-512 | 16 | `424d2fc9…` |
| HAWK-1024 | 0 | `0264ef6f…` |
| HAWK-1024 | 1 | `bd155013…` |
| HAWK-1024 | 2 | `4a448b32…` |
| HAWK-1024 | 16 | `b32dc9d5…` |

Full hex digests: `vectors/json/m_s_ueo_hawk{256,512,1024}.json`.

## wNR: fixed malformed `(pk, sig)` per set

Same `(pk, sig)` as the MBS witness on each parameter set; 100 independent
SHAKE-derived messages per set, all accepted (100/100).

| set | `pk_sha256` (prefix) | trials |
|-----|----------------------|--------|
| HAWK-256 | `ab203c63…` | 100/100 |
| HAWK-512 | `3d67e3d7…` | 100/100 |
| HAWK-1024 | `bd155013…` | 100/100 |

Full hex digests: `vectors/json/wnr_hawk{256,512,1024}.json`.

## Key-generation floor (companion paper)

`KeyNormCheck` threshold `Q_min = ℓ_low`:

| set | `Q_min` | constant-key MBS boundary (empirical) | `32 σ_verify²` |
|-----|---------|---------------------------------------|----------------|
| HAWK-256 | 556 | `K ≤ 23` | ≈ 34.7 |
| HAWK-512 | 2080 | `K ≤ 13` | ≈ 65.0 |
| HAWK-1024 | 7981 | `K ≤ 13` | ≈ 79.0 |

Every witness here has `q00[0] = 1`, far below `Q_min`.
