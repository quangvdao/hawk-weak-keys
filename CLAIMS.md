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
S-DEO, MBS, and wNR.  ADMSW24's Remark 7 (§5.1) goes one step further
and notes that the HAWK specification only states that the design
*facilitates* applying the BUFF transform; ADMSW24 then asserts that
"in the concrete case of HAWK, BUFF security is fulfilled for [the
lighter PS-3] transform, i.e., an application of the full BUFF
transform is not necessary."  The HAWK spec's own statement is the
weaker "facilitates" claim; ADMSW24's Remark 7 is the stronger
"sufficient" claim.  The empirical counterexamples below refute the
stronger claim on MBS and wNR.

The artifact's positive claims are about **public-key inputs that the
HAWK verifier accepts and for which specific structural and quantitative
steps in the BUFF analysis of ADMSW24 §5.1 fail**.  An algebraic NTRU
preimage `(f, g, F, G)` with `f·G − g·F = 1` and the right `(q00, q01)`
exists for these keys; HAWK keygen rejects the preimage on its
minimum-size check, while the verifier imposes no analogous check.  The
section *Why the HAWK proofs in ADMSW24 §5.1 are unsound for this pk*
below walks through the specific lines that the witnesses trip and
shows that the gap is not a missing domain restriction but a
combination of one structural and three quantitative holes shared by
all four HAWK proofs (S-CEO, S-DEO, MBS, wNR).  This artifact ships
empirical counterexamples for MBS, M-S-UEO, and wNR; it does not ship
S-CEO or S-DEO counterexamples, but Flaws 3 and 4 below apply to
those proofs by the same argument.

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
domain on all three parameter sets.  The witness exhibits a public key
for which the MBS proof of ADMSW24 §5.1 has structural and quantitative
holes (see *Why the HAWK proofs in ADMSW24 §5.1 are unsound for this pk*
below).  In particular, the factor `(q01/q00)·f − F` in the proof's
coordinate decomposition of `‖w − w'‖_Q` is *exactly zero* in every
FFT coordinate for the natural algebraic preimage `(f, g, F, G) = (1, 0, 1, 1)`
of this pk, and the proof has no case analysis for that vanishing.

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
public-key domain on all three parameter sets.  The four pk's
correspond to algebraic preimages `(f, g, F, G) = (1, 0, a, 1)` for
`a ∈ {0, 1, 2, 16}`; they share the same `f, g, G` and differ only in
`F`, so the structural degeneracy `(q01/q00)·f − F = a·1 − a = 0` of
the MBS coordinate decomposition holds for every member of the family.
The S-CEO θ-ball-volume bound that ADMSW24 reuses for M-S-UEO inherits
the same scale gap (see *Why the HAWK proofs in ADMSW24 §5.1 are
unsound for this pk* below).

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
be.  ADMSW24 §5.1's wNR analysis reduces directly to the S-CEO θ-ball
volume estimate ("amounts to the same probability as computed in the
proof of S-CEO"); that estimate is computed for honest-scale
`(q00, q01)` and is wildly wrong for our malformed pk, where the
verifier's threshold ball encompasses essentially the entire signature
space (see *Why the HAWK proofs in ADMSW24 §5.1 are unsound for this
pk* below).  Turning this attack shape into a formal wNR adversary against
ADMSW24's exact game reduces to checking that the entropy and
oracle-access conditions of that game are satisfied by the
construction; the message-independence shown empirically here is the
core ingredient.

## Why the HAWK proofs in ADMSW24 §5.1 are unsound for this pk

The witnesses do not exhibit a public key outside the proof's *domain*:
the algebraic preimage `(f, g, F, G) = (1, 0, 1, 1)` is a perfectly
valid HAWK secret-key matrix `B = ((f, F),(g, G))` with
`Q = B^* B = ((1, 1),(1, 2))` and `f·G − g·F = 1`.  What the witnesses
exhibit is that the BUFF analysis of HAWK in ADMSW24 §5.1 has specific
structural and quantitative steps that fail for this `B`.  This
section walks through them.

ADMSW24 §5.1 contains four proofs (S-CEO, S-DEO, MBS, wNR), and the
flaws below apply to all four:

- The MBS proof falls to Flaws 1, 2, and 4 directly, and is refuted
  by `vectors/kat/mbs_*.rsp`.
- The wNR proof reduces "to the same probability as computed in the
  proof of S-CEO", inheriting Flaws 3 and 4, and is refuted by
  `vectors/kat/wnr_*.rsp`.
- The M-S-UEO situation, although M-S-UEO is not in ADMSW24's own
  framework, falls to the same structural and counting argument and
  is refuted by `vectors/kat/m_s_ueo_*.rsp`.
- The S-CEO and S-DEO proofs use the θ-ball volume estimate of
  Flaw 3 and the implicit existential of Flaw 4.  This artifact does
  not ship empirical witnesses against the S-CEO or S-DEO games for
  the `(q00, q01) = (1, a)` family; the artifact's claim about
  S-CEO / S-DEO is restricted to the *proofs* being unsound on the
  verifier-accepted public-key domain, not to the *games* being lost
  on this specific family.

### Setup, restated from ADMSW24 §5.1

Verification accepts `(pk, msg, sig = (salt, s_1))` iff `‖w‖_Q ≤ θ`,
with `w = (w_0, w_1) = (h_0 − 2 s_0, h_1 − 2 s_1)`,
`(h_0, h_1) = H(M ‖ salt)`, and `s_0` reconstructed by HAWK
Algorithm 18 from `(q00, q01, w_1, h_0)`.  ADMSW24 §5.1 uses the
existence of an NTRU basis `B = ((f, F),(g, G))` with `Q = B^* B` and
`f·G − g·F = 1`; this basis need not be the honest signer's, only an
algebraic preimage of `(q00, q01)`.

### Flaw 1 (structural): the factor `(q01/q00)·f − F` can be zero

For two messages `msg ≠ msg'` accepting under the same `(pk, sig)`,
ADMSW24 (page 22) writes

```
‖w − w'‖_Q = ‖B(w − w')‖
           = ‖( (h_1 − h_1')·((q01/q00)·f − F) + f·(ε + ε'),
                (h_1 − h_1')·((q01/q00)·g − G) + g·(ε + ε') )‖,
```

with `ε, ε' ∈ [−½, ½)` arising from
`s_0 = h_0/2 − (q01/q00)(h_1/2 − s_1) + ε`, and concludes that this falls below `2θ`, twice the verification radius, only with negligible probability, because
`(q01/q00)·f − F` and `(q01/q00)·g − G` are fixed values, while
`h_1 − h_1'` and `ε + ε'` are random."

For the algebraic preimage `(f, g, F, G) = (1, 0, 1, 1)` of our
witness, evaluated in every Fourier coordinate:

```
(q01/q00)·f − F = 1·1 − 1 = 0
(q01/q00)·g − G = 1·0 − 1 = −1
f               = 1
g               = 0
```

The first coordinate of `B(w − w')` then collapses to
`f·(ε + ε') = ε + ε'`, of size `O(1)` *regardless of* `h_1 − h_1'`,
and the second coordinate collapses to `−(h_1 − h_1')`, with no
honest-norm-of-`g` factor multiplying it.  The proof's argument
requires the random `h_1 − h_1'` contribution to dominate; for this
preimage, it doesn't.  ADMSW24 §5.1 has no case analysis for
`(q01/q00)·f − F = 0`, even though this happens for *any* algebraic
preimage with `f·q01 = F·q00` (a subspace, not a measure-zero point).

### Flaw 2 (quantitative): the "fixed values" need to be honest-scale

Even where the "fixed values" are nonzero (the `−1` in the second
coordinate above), the proof's "negligible probability" conclusion
silently requires `(q01/q00)·f − F`, `(q01/q00)·g − G`, `f`, and `g`
to have magnitudes `Θ(σ_kg √n)`, where `σ_kg` is the key-generation
standard deviation.  Honest keygen rejects preimages
with `‖f‖² + ‖g‖²` below a parameter-dependent minimum of order
`2 σ_kg² n` (roughly `1.5 × 10³` for HAWK-512), so honest pk's only
ever expose preimages at this scale.  The verifier imposes no such
minimum: it accepts `(q00, q01) = (1, 1)`, for which `(1, 0, 1, 1)` has
`‖f‖² + ‖g‖² = 1`, three orders of magnitude below keygen's minimum.
At this scale the random-`h_1 − h_1'` term contributes at most
`‖h_1 − h_1'‖² ≈ n/2`, well below the threshold radius `(2θ)² ≈ 64 n`
for HAWK-512.

Concretely, the verifier's quadratic norm for our pk simplifies (via
`q11 = (1 + |q01|²)/q00`, the implicit `det Q = 1` in HAWK
Algorithm 19) to

```
‖w‖²_Q = q00·|w_0 + (q01/q00)·w_1|² + (1/q00)·|w_1|²
       = |w_0 + w_1|² + |w_1|²,
```

with `|w_0 + w_1|_∞ ≤ 1` per coefficient (HAWK Algorithm 18's
rounding has slack) and `|w_1|² = ‖h_1‖² ≈ n/2` from our `s_1 = 0`.
Total `(1/n)·‖w‖²_Q ≈ 1`, well below the parameter-set threshold
`θ² ≈ 16` for HAWK-512.  The form is structurally identical for
HAWK-256 and HAWK-1024 with comparable margin, which matches the
empirical 100 / 100 acceptance for wNR on every parameter set.

### Flaw 3 (counting): the S-CEO / wNR θ-ball estimate is honest-only

§5.1's S-CEO analysis estimates "for the parameters in HAWK, a θ-ball
is of size `2^(31·3)`, while the space of possible values is
`2^(31·256)`, so a random value will be in a θ-ball with probability
about `2^(−31·253)`."  This volume is the count of integer points in
the ball `{w : ‖w‖_Q ≤ θ}` *for honest-distributed `(q00, q01)`*.
In our malformed key (with `q00 = 1` constant, while honest
`q00[0] = ‖f‖² + ‖g‖²` is bounded below by keygen's minimum of
order `2 σ_kg² n`, roughly `1.5 × 10³` for HAWK-512, three orders of
magnitude above ours), the same Q-ball encompasses essentially the
entire signature space.  ADMSW24 §5.1's
wNR analysis reuses this count verbatim ("amounts to the same
probability as computed in the proof of S-CEO") and inherits the same
gap; the M-S-UEO bound in the same section relies on the same
volume-counting argument.

The 100 / 100 wNR acceptance across all three parameter sets, with
messages drawn from a SHAKE-keyed PRF whose output is unrelated to
the malformed pk, is the direct experimental witness for this flaw.

### Flaw 4 (quantification): implicit existential over `(f, g, F, G)`

ADMSW24's argument is parametrised by *some* `B = ((f, F),(g, G))`
with `Q = B^* B` and `f·G − g·F = 1`; given `(q00, q01)`, multiple
`B` satisfy this.  For honest pk keygen's minimum pins all
preimages to honest scale, so picking any honest `B` for the proof is
harmless.  For our malformed family `(q00, q01) = (1, a)` the
verifier accepts preimages of arbitrarily small norm, including the
explicit `(1, 0, a, 1)` for which the structural degeneracy of
Flaw 1 holds.  The proof never quantifies over preimages and silently
substitutes the honest one.

### Smallest classification of the gaps

1. *(Structural.)*  No case analysis when `(q01/q00)·f − F = 0` (or
   `(q01/q00)·g − G = 0`) in the MBS / `‖w − w'‖_Q` coordinate
   decomposition.
2. *(Quantitative.)*  No quantitative lower bound on the magnitudes
   of `(q01/q00)·f − F`, `(q01/q00)·g − G`, `f`, `g` relative to the
   threshold radius `θ`.
3. *(Counting.)*  Honest-distribution θ-ball volume estimate reused
   verbatim for S-CEO, M-S-UEO, and wNR without re-deriving on the
   verifier-accepted domain.
4. *(Quantification.)*  Implicit existential quantifier over
   algebraic preimages `(f, g, F, G)` not restricted to honest-norm
   preimages.

Closing these gaps requires either (a) tightening the verifier with a
candidate public-key validity check that excludes malformed `(q00, q01)`,
or (b) tightening the proof (re-quantifying over all algebraic
preimages and re-deriving the θ-ball count over the verifier-accepted
domain).  This artifact is silent on which check is preferred; it
only documents that without one of them the BUFF proofs are unsound
for the verifier as specified.

A natural first guess is a per-Fourier-coordinate lower bound
`min_u q00_u ≥ μ`, possibly combined with a bound on
`K(pub) = max_u |q01_u| / sqrt(q00_u)`, both checkable in `O(n log n)`
at verify time.  Empirical sweeps over the constant-`q00` adversarial
family rule this out: the constant family `q00 = K, q01 = a` for `K`
intermediate (e.g. `K = 8` for HAWK-256) passes any honestly calibrated
per-coordinate lower bound `min_u q00_u ≥ μ` and *still* breaks MBS / wNR.

The load-bearing public-key validity quantity is instead the
constant term `q00[0] = ‖f‖² + ‖g‖²`, which equals the *average*
of the Fourier coordinates and is exactly the quantity HAWK keygen enforces:
honest keygen resamples `(f, g)` until `‖f‖² + ‖g‖² ≥ ℓ_low`
with `ℓ_low = 556 / 2080 / 7981` for HAWK-256/512/1024, while the
constant-`q00` MBS attack only survives for `K` up to about
`23 / 13 / 13` (empirically) and is provably defeated once
`K > 32 σ_verify² ≈ 34.7 / 65.0 / 79.0`.  Setting the verifier-side
threshold `Q_min = ℓ_low = 556 / 2080 / 7981` therefore sits an order of
magnitude above the attack boundary and exactly at keygen's minimum,
so every honest key passes by construction (with probability 1, not
merely overwhelmingly) and the entire constant-`q00` family is
rejected.  This single `i32` comparison `q00[0] ≥ Q_min` is the
`KeyNormCheck` predicate.

The companion paper's positive results are: exact honest acceptance under
`KeyNormCheck`; constant-`q00` MBS closure under that floor (real-valued
norm); and a stronger per-coordinate spectral-floor theorem that honest
keys typically fail.  Non-constant uneven keys under plain
`KeyNormCheck`, and bit-exact `PolyQnorm` soundness, remain open.
This artifact restricts itself to empirical witnesses against the unmodified
verifier.

## Companion paper: bounds, proof status, and open problems

This artifact documents counterexamples against the **unmodified** HAWK
verifier.  The companion paper records what HAWK **key generation** already
enforces and what would follow if verification applied the same bounds.
It makes **no claim** that doing so fully restores BUFF security.

### S-CEO and S-DEO (games not refuted here)

This artifact ships no S-CEO or S-DEO counterexamples for the
`(q00, q01) = (1, a)` family, and extended malformed-key search finds
none.  The ADMSW24 §5.1 *proofs* of S-CEO and S-DEO remain unsound on
the verifier-accepted domain (Flaws 3 and 4).  A repaired two-branch
argument in the companion paper (splitting on `max_u q00_u`) suggests
the *games* may survive this family when the adversary must reuse an
honest signature; that argument is still a sketch.

### KeyNormCheck (norm floor matching key generation)

Empirical sweeps over the constant family, sparse non-constant
perturbations, and 75600 dense non-constant `q00` shapes find **zero**
MBS or wNR accepts once `q00[0] ≥ Q_min` at
`Q_min = ℓ_low = 556 / 2080 / 7981`.
Honest HAWK keygen passes `KeyNormCheck` with probability 1, because
keygen's minimum `‖f‖² + ‖g‖² ≥ ℓ_low` equals `q00[0]`.
Implementation cost: one signed comparison after `decode_public`.

An earlier draft used a per-Fourier-coordinate lower bound `min_u q00_u ≥ μ_min`;
constant-`q00` adversaries (`K = 8` on HAWK-256) refute that predicate.
The load-bearing quantity is the time-domain constant `q00[0]`.

In the companion paper this floor is proved to defeat the entire
**constant-`q00`** MBS attack class (including the witnesses here) when
the norm is evaluated as the intended real quadratic form.
Whether plain `KeyNormCheck` implies MBS for **non-constant** uneven
spectra remains open.

### KeyIdentityCheck (algebraic norm identity)

Separately, the paper defines `KeyIdentityCheck`: the decoded key must
yield an integral self-adjoint `q11 = (1 + q01 q01*)/q00` in range.
Without it, the reference verifier's two-prime `PolyQnorm` need not
equal the quadratic form the positive theorems reason about (e.g.
`q00 = 2, q01 = 0` decodes but has no integer `q11`).
The artifact does not implement or test this predicate; it is recorded
in the paper only to state conditional theorems precisely.

### Per-coordinate spectral floor (stronger bound, not deployable as-is)

The paper also proves that requiring **every** Fourier coordinate
`q00_u ≥ μ > 32 σ_verify²` would block arbitrary keys in the same
real-valued framework.  Honest HAWK keys often **fail** that stronger
floor, so it is a mathematical conditional result, not a practical
verifier recommendation.  This replaces an earlier draft's
`KeyShapeCheck` (effective spread / peak-to-average) route, which the
paper no longer states.

### Proof-status summary (companion paper)

| Statement | Status in paper |
|-----------|-----------------|
| Counterexamples (MBS, M-S-UEO, wNR) | Constructive + verified here |
| ADMSW24 §5.1 unsound on verifier-accepted domain | Four identified gaps |
| Honest keys pass `KeyNormCheck` | Exact theorem |
| Constant-`q00` MBS under `KeyNormCheck` | Theorem (real-valued norm) |
| Arbitrary keys under per-coordinate floor | Theorem (real-valued norm; honest keys often fail floor) |
| Non-constant `q00` under plain `KeyNormCheck` | **Open** |
| Full BUFF restoration from norm floor alone | **Not claimed** |
| Reference `PolyQnorm` = intended form on all accepted keys | Requires `KeyIdentityCheck`; not claimed for every decoded pk |

## Cascade into Düzlü, Struck 2024/1669

ePrint 2024/1669 (*Message-Bound Signatures and Weak Keys*) gives a
generic reduction: if Σ has MBS, then PS-3[H, Σ] has S-UEO and a form
of non-resignability, both with quadratic loss.  Its central
conceptual claim is that *MBS is the right formalisation of "the
scheme has no effective weak keys"*: a public key that verifies
multiple messages with a single signature is exactly what MBS forbids.

HAWK is structurally a PS-3-transformed scheme in the sense of
2024/1669.  Its verification target is `M = H(msg ‖ H(pk))` (ADMSW24
Fig. 7, line 3), which is the PS-3 hash up to recoding of `pk` through
an inner hash.  ADMSW24's Remark 7 makes this PS-3 reading explicit.
A reader applying 2024/1669 to HAWK uses ADMSW24 Table 1's MBS ✓ as
input and would conclude that HAWK has S-UEO and (a form of) wNR
post-PS-3 essentially "for free".

The MBS counterexamples in this artifact close that route at HAWK:

- ADMSW24's claim that HAWK has MBS is empirically false on the
  verifier-accepted public-key domain.
- The malformed `(pk, sig)` of Claim 1 is exactly the kind of
  *effective weak key* that 2024/1669's narrative says MBS rules out.

There is no formal contradiction in 2024/1669 itself: its theorem is
conditional on Σ having MBS, and that hypothesis fails for HAWK.
What this artifact removes is the example landscape: 2024/1669 lifts
ADMSW24 Table 1's HAWK row as the canonical "MBS holds" lattice
case, and that anchor does not survive the verifier-accepted domain.

## What is NOT claimed

The artifact does **not** claim, and the experiments do **not** support:

1. **HAWK SUF-CMA is broken on honestly generated keys.**  The witnesses
   use adversarially chosen public keys outside the support of HAWK
   keygen.  Standard EUF-CMA / SUF-CMA gives the adversary an honestly
   generated public key; that game is not attacked here.

2. **An empirical S-CEO or S-DEO witness for this weak-key family.**
   ADMSW24's S-CEO and S-DEO games require the adversary to use a
   signing-oracle signature on the honest public key.  This artifact
   does not exhibit S-CEO or S-DEO witnesses for the
   `(q00, q01) = (1, a)` family and ships only the positive MBS /
   M-S-UEO / wNR vectors.  Note that this is *not* a claim that the
   S-CEO and S-DEO proofs in ADMSW24 §5.1 are sound: those proofs use
   the same θ-ball volume estimate (Flaw 3) and the same implicit
   existential over algebraic preimages (Flaw 4) as the MBS and wNR
   proofs, and are unsound on the verifier-accepted public-key domain
   by the same argument.  The artifact only declines to assert that
   the games' conclusions are also broken on this specific family.

3. **The malformed pk has no algebraic NTRU preimage.**  False.  For
   the constant family `q00 = 1, q01 = a` there is the explicit
   preimage `(f, g, F, G) = (1, 0, a, 1)` with `f·G − g·F = 1` and
   matching `(q00, q01, q11) = (1, a, 1 + a²)` (the implicit `q11`
   under HAWK Algorithm 19).  HAWK keygen rejects this `(f, g)`
   because `‖f‖² + ‖g‖² = 1` is far below the parameter-dependent
   keygen minimum; the verifier never imposes such a
   check.  The MBS / M-S-UEO / wNR proofs in ADMSW24 §5.1 use this
   preimage in their coordinate decomposition, and the *structural*
   degeneracy `(q01/q00)·f − F = 0` is what trips the MBS proof; it
   is not the absence of an algebraic preimage that drives the
   counterexample.  See *Why the HAWK proofs in ADMSW24 §5.1 are
   unsound for this pk* above.

4. **Acceptance is sensitive to the encoder.**  The shipped `pk` and
   `sig` bytes round-trip cleanly through the official `decode_public`
   and `decode_sign`; they are valid encoded HAWK objects in every
   spec-level sense except provenance from honest keygen.

## Disclosure boundary

This artifact is suitable for accompanying a paper that:

- claims falsification of MBS, M-S-UEO, and wNR over the
  HAWK verifier's accepted, byte-decodable public-key domain on all three parameter sets,
- frames the result as specific structural and quantitative gaps in
  the BUFF analysis of HAWK in ADMSW24 §5.1, exposed by the
  verifier-accepted public-key domain (see *Why the HAWK proofs in
  ADMSW24 §5.1 are unsound for this pk* for the line-by-line account),
- records (separately, not in this artifact) that HAWK key generation
  already enforces a norm floor (`KeyNormCheck`: `q00[0] ≥ ℓ_low`) that
  rejects every witness here with probability 1 on honest keys, and
  states conditional theorems for what enforcing that floor would buy
  for constant-`q00` keys when the norm matches the intended quadratic
  form (`KeyIdentityCheck`); it does not claim full BUFF restoration.

It is **not** suitable as backing for SUF-CMA, EUF-CMA, S-CEO, or S-DEO
claims.
