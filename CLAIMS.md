# Claims

This document records exactly what the artifact does and does not show.
It is intentionally narrow: every claim below is the literal observation
of running both verifiers on the shipped `vectors/kat/*.rsp` files.
Anything in the literature surrounding these games is cited explicitly.

## Notation and references

- HAWK refers to HAWK Round 2 as specified in the HAWK v1.1 specification
  document, dated 2025-02-05.
- The vendored implementations under `third_party/hawk-sign-submission/`
  are the authors' own published reference implementations (C and Python).
- BUFF properties are taken from:
  - Cremers, Düzlü, Fiedler, Fischlin, Janson, *BUFFing Signature Schemes
    Beyond Unforgeability*, IACR ePrint 2020/1525.
  - Aulbach, Düzlü, Meyer, Struck, Weishäupl, *Hash Your Keys Before
    Signing: BUFF Security of the Additional NIST PQC Signatures*, IACR
    ePrint 2024/591 (henceforth ADMSW24).
  - Düzlü, Struck, *Message-Bound Signatures and Weak Keys*, IACR ePrint
    2024/1669.

The HAWK v1.1 spec states that
*"HAWK achieves the BUFF security properties as is [ADMSW24]"*
in the advantages section.  ADMSW24 marks HAWK as satisfying S-CEO,
S-DEO, MBS, and wNR.

The artifact's positive claims are about **public-key inputs that the
HAWK verifier accepts but that fall outside the implicit public-key
domain of the ADMSW24 analysis**.  The HAWK keygen would reject the
underlying `(f, g)` for these keys; the verifier does not.

## Threat model

For each claim, the adversary outputs a HAWK public key that decodes
cleanly under `decode_public` (HAWK Algorithm 9) and a signature that
decodes cleanly under `decode_sign` (HAWK Algorithm 11).  The adversary
does **not** have to come from honest `crypto_sign_keypair`.  This is
the standard BUFF threat model: malicious key generation is in scope.

## Claim 1: MBS counterexample

**Game (ADMSW24 §3, MBS).**  An adversary outputs `(pk, sig, m, m')`
with `m ≠ m'` such that `Verify(pk, m, sig) = Verify(pk, m', sig) = 1`.

**Witness.**  For each of `Hawk-256`, `Hawk-512`, `Hawk-1024`, taking
- `q00 = constant polynomial 1`,
- `q01 = constant polynomial 1`,
- `salt = all zeros`,
- `s1 = constant polynomial 0`,
encoding via `Extra/hawk-py/codec.py:encode_public` and `:encode_sign`,
and using the two ASCII messages
- `m = "HAWK malformed-key MBS counterexample message 0"`,
- `m' = "HAWK malformed-key MBS counterexample message 1"`,
both `Verify(pk, m, sig)` and `Verify(pk, m', sig)` accept under both the
unmodified C reference (`hawk_verify_finish`) and the unmodified Python
reference (`hawkverify`).

This is `vectors/kat/mbs_hawk{256,512,1024}.rsp`.

**Conclusion.**  MBS is falsified over the verifier-accepted public-key
domain on all three parameter sets.  The MBS proof in ADMSW24 implicitly
restricts to a narrower public-key-validity domain than the byte-level
verifier; the artifact exhibits a public key that is valid for `Verify`
but for which MBS does not hold.

## Claim 2: M-S-UEO counterexample

**Game (ADMSW24 §3, M-S-UEO; Cremers et al. 2020/1525).**  An adversary
outputs `(pk, pk', m, sig)` with `pk ≠ pk'` such that
`Verify(pk, m, sig) = Verify(pk', m, sig) = 1`.  Both public keys may be
adversarially chosen ("Malicious-Strong-Universal-Exclusive-Ownership").

**Witness.**  For each of `Hawk-256`, `Hawk-512`, `Hawk-1024`, taking
- `q00 = constant polynomial 1`,
- `q01 = constant polynomial a` for `a ∈ {0, 1, 2, 16}`,
- `salt = all zeros`, `s1 = constant polynomial 0`,
- `m = "HAWK malformed-key M-S-UEO counterexample message"`,
the four resulting public keys are pairwise distinct (different SHA-256)
and the same `(m, sig)` accepts under all four under both verifiers.

This is `vectors/kat/m_s_ueo_hawk{256,512,1024}.rsp`.

**Conclusion.**  M-S-UEO is falsified over the verifier-accepted
public-key domain on all three parameter sets.

## Claim 3: wNR shape

**Game (ADMSW24 §3, wNR).**  Informally: an adversary that receives an
honest signature on an unknown high-entropy challenge message cannot
output a fresh signature on that same unknown message under another key
except with negligible probability.  The standard reduction to MBS asks
the adversary to commit a `(pk', sig')` that opens to the unknown
challenge message.

**Witness shape.**  For each of `Hawk-256`, `Hawk-512`, `Hawk-1024`,
taking the fixed malformed `(pk, sig)` from Claim 1 (`q00 = const 1`,
`q01 = const 1`, `salt = 0`, `s1 = const 0`) and 100 SHAKE-derived
hidden challenge messages
- `m_i = SHAKE256("hawk-weak-keys wNR challenge " || le8(i))[0..32]`,
every record `(pk, m_i, sig)` accepts under both verifiers.  100 / 100
acceptance for `i = 0..99`, all three parameter sets.

This is `vectors/kat/wnr_hawk{256,512,1024}.rsp`.

**Conclusion.**  The fixed malformed `(pk, sig)` opens to every sampled
high-entropy challenge message.  This is the attack shape against wNR
when the adversary is allowed to choose `pk` adversarially: it commits
to a fixed `(pk, sig)` that ignores the given honest signature and
trivially opens to whatever the unknown challenge message turns out to
be.  The artifact exhibits the message-independence directly; turning
this shape into a formal wNR adversary against ADMSW24's exact game
reduces to checking that the entropy and oracle-access conditions of
that game are satisfied by the construction.

## What is NOT claimed

The artifact does **not** claim, and the experiments do **not** support:

1. **HAWK SUF-CMA is broken on honestly generated keys.**  The witnesses
   use adversarially chosen public keys outside the support of HAWK
   keygen.  Standard EUF-CMA / SUF-CMA gives the adversary an honestly
   generated public key; that game is not attacked here.

2. **S-CEO or S-DEO is broken with honest-signature reuse.**  ADMSW24's
   S-CEO and S-DEO games require the adversary to use a signing-oracle
   signature on the honest public key.  The natural attack of reusing
   honest C-keygen signatures under the malformed public-key family
   was tested over tens of thousands of trials in our companion probes
   and produced no hits.  This artifact ships the positive MBS /
   M-S-UEO / wNR results only.

3. **No NTRU basis exists for the malformed key.**  For the constant
   family `q00 = 1, q01 = a` there is a formal NTRU basis
   `(f, g, F, G) = (1, 0, a, 1)` with `f·G - g·F = 1` and the right
   `q00, q01`.  The HAWK keygen rejects this `(f, g)` because
   `‖f‖² + ‖g‖²` is far below the keygen minimum norm check.  So the
   issue is not "no algebraic preimage exists"; it is "no honest-keygen
   preimage exists, but the verifier accepts anyway".

4. **Acceptance is sensitive to the encoder.**  The shipped `pk` and
   `sig` bytes round-trip cleanly through the official `decode_public`
   and `decode_sign`; they are valid encoded HAWK objects in every
   spec-level sense except provenance from honest keygen.

## Disclosure boundary

This artifact is suitable for accompanying a paper that:

- claims byte-level falsification of MBS, M-S-UEO, and wNR over the
  HAWK verifier's accepted public-key domain on all three parameter sets,
- frames the result as a gap between the verifier-accepted public-key
  domain and the public-key domain of the BUFF analysis in ADMSW24,
- proposes (separately, not in this artifact) a public-key validity
  predicate that excludes this family while accepting honestly generated
  keys with overwhelming probability.

It is **not** suitable as backing for SUF-CMA, EUF-CMA, S-CEO, or S-DEO
claims.
