# Vendored Third-Party Sources

The artifact vendors the HAWK Round 2 NIST submission unmodified, both as
the original archive (for byte-level integrity) and extracted (for use by
the verifier drivers).

## Provenance

| field          | value |
|----------------|-------|
| source URL     | <https://hawk-sign.info/submission.zip> |
| last-modified  | Wed, 21 May 2025 09:11:44 GMT |
| size           | 6,111,768 bytes |
| SHA-256        | `301ebfd625877a9997bad6441bc9d69b01df5f6aba35332caa113f6462a96f86` |

To re-fetch and confirm:

```bash
curl -fL -o /tmp/hawk-submission.zip https://hawk-sign.info/submission.zip
shasum -a 256 /tmp/hawk-submission.zip
# 301ebfd625877a9997bad6441bc9d69b01df5f6aba35332caa113f6462a96f86  /tmp/hawk-submission.zip
```

The archive is the official HAWK Round 2 submission to the NIST PQC
"Additional Digital Signatures" process.  It contains:

- `Reference_Implementation/hawk{256,512,1024}/`: portable C reference.
- `Optimized_Implementation/avx2/hawk{256,512,1024}/`: AVX2-accelerated C.
- `Extra/hawk-py/`: Python reference, the spec authors' own pure-Python implementation.
- `KAT/`: the official NIST PQC `.req` / `.rsp` test vectors and intermediate-value files.
- `Supporting_Documentation/`: spec PDF and supporting material.

## What the artifact uses

The artifact's verifier drivers and generator depend on:

- `Extra/hawk-py/{codec.py, params.py, verify.py, sign.py, poly.py, rngcontext.py}` (Python reference).
- `Reference_Implementation/hawk512/{hawk_kgen.c, hawk_sign.c, hawk_vrfy.c, ng_*.c, sha3.c, hawk.h, hawk_inner.h, hawk_config.h, sha3.h, modq.h}` (C reference core).

These are used **unmodified**.  The artifact does not patch, fork, or
shadow any of these files.  The artifact contributes only:

- `src/generate_vectors.py` (uses `Extra/hawk-py/codec.py` to encode pk/sig).
- `drivers/verify_kat.c` (calls `hawk_verify_finish` from the vendored C reference).
- `drivers/verify_kat.py` (calls `hawkverify` from the vendored Python reference).

## Why we ship `submission.zip` AND the extracted tree

The unextracted `submission.zip` is the byte-level provenance anchor: any
reviewer can verify the SHA-256 against the URL above without trusting
the extraction step.  The extracted tree is what the build and runtime
actually consume.  An integrity check ensures the two stay in sync:

```bash
( cd third_party && unzip -q submission.zip -d /tmp/hawk-resign \
  && diff -r hawk-sign-submission/hawk-submission /tmp/hawk-resign/hawk-submission )
```

## Licensing

The vendored implementations follow the licensing stated in the
HAWK Round 2 submission.  See:

- `hawk-sign-submission/hawk-submission/Extra/hawk-py/LICENSE.txt`
  for the Python reference license,
- `hawk-sign-submission/hawk-submission/README.txt` for the C reference
  documentation and contact information.

The artifact does not relicense any vendored file.  The artifact's own
files (`README.md`, `CLAIMS.md`, `src/`, `drivers/`, `docker/`,
`vectors/`, this `third_party/README.md`) are released under the MIT
License; see the top-level `LICENSE` file at the repository root.
