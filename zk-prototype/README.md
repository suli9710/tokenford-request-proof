# Legacy signed-claims circuit and synthetic demo

This directory supplies the signed JWT/plan constraints used by the interactive experiment and keeps a legacy standalone synthetic demo for review. The primary public flow is ../request-proof. No real account history proof, stable real-account digest, or account verification receipt is included.

The generic official_prove.mjs accepts user-supplied data over stdin; it contains no production collector or bundled credential. verify.mjs and verify_official.py are generic verification source. Their historical official-account files are deliberately absent, so verify_official.py has no real proof to verify by default. Do not interpret source availability or old development claims as new real-account evidence. The legacy account-digest construction is reviewable code, not evidence about any actual account in this fork.

The supported review entry is ../review.py, documented in the root README. Its build command installs exact npm versions and public Noir source dependencies, compiles circuits, and obtains locked public CRS parameters. npm run demo and npm run verify remain legacy synthetic demonstrations, separate from the primary interactive flow. Current release validation is recorded separately in ../VALIDATION.md when supplied.

The fixed inherited toolchain is Noir 1.0.0-beta.14 and Barretenberg 3.0.0-nightly.20251104 with explicit zero-knowledge mode. sources-lock.json and package-lock.json retain dependency integrity material. Release preparation preserves the historical circuit bytecode/VK identities, but the maintainer recalculates source-file hashes for this new candidate. The resulting reviewed-build.json and root manifest require independent acceptance and are not external audit evidence. Reviewers must not regenerate them to hide a mismatch.

The circuit constrains issuer, signature, nested plan/account claims, and credential validity at a selected statement time. It does not establish current payment/subscription state, the account pool, a live request, or model weights by itself. A selected public statement time is not an upstream live-query timestamp. Interactive freshness and request association belong to the separate request-proof protocol.

Vendored license files present in the input archive are kept unchanged. Missing upstream license material is listed in ../THIRD_PARTY_LICENSE_STATUS.md. Apache-2.0 for original project work does not replace third-party terms. See ../HISTORICAL_RESULTS.md for the V1/V2 history boundary.
