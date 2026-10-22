# Third-party license status

Status: **PARTIAL — three exact-version dependency licenses remain unresolved.** Root original-project Apache-2.0 material and TLSNotary license-option documentation are now present. This is provenance work, not legal clearance or permission to distribute unresolved components.

## Original project scope

The user selected Apache-2.0 for original project files and original modifications. Root LICENSE is the unmodified official Apache-2.0 standard text; NOTICE limits its scope and preserves third-party terms. No author/copyright-holder line was guessed. Copied or modified third-party portions retain their original terms.

- Official text: https://www.apache.org/licenses/LICENSE-2.0.txt
- SHA256: `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
- Copies: `LICENSE` and `licenses/Apache-2.0.txt`.

## TLSNotary exact source

Pinned commit: `9a3d73c5bdeeab0255bdb05c89116554cebf6dbe`. Its README explicitly offers Apache-2.0 OR MIT for **all crates**, at the recipient's option. This package selects Apache-2.0, including crates whose individual manifest omits a license field. The TLS client/core OR declarations also allow Apache-2.0. Individual source/README attribution and third-party statements remain unchanged.

The exact upstream archive has no LICENSE/COPYING/NOTICE file; the standard selected license text is supplied from apache.org, without inventing an upstream copyright notice. `licenses/TLSNotary-LICENSE-NOTE.md`, the saved upstream README and per-crate inventory retain the evidence.

- Archive: https://codeload.github.com/tlsnotary/tlsn/tar.gz/9a3d73c5bdeeab0255bdb05c89116554cebf6dbe
- Archive SHA256: `fb6277f833f5763b0fbefd423e1f3e615269b0430e9729b3b602626c6d165811`

| Crate | Upstream declaration | Selected |
| --- | --- | --- |
| `tlsn-attestation` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-cipher` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn-deap` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-hmac-sha256` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn-key-exchange` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn-core` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn-data-fixtures` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-examples` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-formats` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-harness-core` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-harness-executor` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-harness-plot` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-harness-runner` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-mpc-tls` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn-server-fixture-certs` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-server-fixture` | `omitted; explicit all-crates README grant` | Apache-2.0 |
| `tlsn-tls-backend` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn-tls-client-async` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn-tls-client` | `Apache-2.0 OR ISC OR MIT` | Apache-2.0 |
| `tlsn-tls-core` | `Apache-2.0 OR ISC OR MIT` | Apache-2.0 |
| `tls-server-fixture` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn` | `MIT OR Apache-2.0` | Apache-2.0 |
| `tlsn-wasm` | `MIT OR Apache-2.0` | Apache-2.0 |

## Vendored Noir exact-version inventory

All 20 source archives were fetched from their official repositories and matched the already locked `.archive-sha256` values. All 17 existing vendored LICENSE files match their locked upstream originals byte-for-byte. No source or lock file was edited. Each archive was checked for LICENSE/COPYING/NOTICE and license/copyright/SPDX statements.

| Component | Result |
| --- | --- |
| `zk-prototype/vendor/noir-lang__keccak256__v0.1.1` | **UNRESOLVED**: no exact-version grant/text |
| `zk-prototype/vendor/noir-lang__noir-bignum__v0.8.0` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_base64__v0.4.2` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_check_shuffle__v0.2.0` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_check_shuffle__v0.2.1` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_json_parser__7c28610067af182d4b03bde406f1b3dfbbaa6f1f` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_json_parser__dc8ad05fd63ef7518bf3adf3e5b61a87feb143b8` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_json_parser__v0.4.0` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_sort__v0.2.2` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_sort__v0.3.0` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_sort__v0.4.0` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__noir_string_search__v0.3.3` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__poseidon__v0.1.1` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__poseidon__v0.3.0` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/noir-lang__sha256__v0.2.1` | **UNRESOLVED**: no exact-version grant/text |
| `zk-prototype/vendor/olehmisar__nodash__v0.42.0` | **UNRESOLVED**: no exact-version grant/text |
| `zk-prototype/vendor/zac-williamson__sha1__v0.11` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/zkemail__noir-jwt__v0.5.1` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/zkpassport__noir_rsa__v0.9.1` | Apache-2.0 text preserved; exact upstream bytes matched |
| `zk-prototype/vendor/zkpassport__sha512__v0.1.0` | Apache-2.0 text preserved; exact upstream bytes matched |

No upstream NOTICE file exists in the inspected archives. License text and any source copyright/attribution remain preserved; source notices are not replaced by this inventory.

## Unresolved components

The pinned official archives for `noir-lang/keccak256 v0.1.1`, `noir-lang/sha256 v0.2.1`, and `olehmisar/nodash v0.42.0` contain no license/copyright/SPDX declaration or LICENSE/COPYING/NOTICE file. Archive member indices, origin URLs, and verified hashes are saved under `licenses/provenance/`. Copies of their README/Nargo source text have been removed; the inventory retains only paths, URLs and digests. Absence of a file does not authorize Apache-2.0 relicensing. A later/different branch license must not be silently treated as a license for these exact versions.

Resolution requires an applicable grant from the rights holder, or replacing/removing the dependencies in a separately reviewed source change. No license was requested from another person. These three items block a complete dependency-closure or derived-artifact release. The present source-only package excludes these directories and compiled circuit artifacts, retains their fixed source identities for local inspection, and does not represent the entire dependency closure as openly licensed.

## Machine-readable provenance

`licenses/license-inventory.json` records every fetched source URL, pinned ref, archive digest, evidence-file digest, TLSNotary crate declaration, vendored Noir text comparison, and unresolved item. Only public source license evidence was fetched; no production access, credentials, real model requests, builds, or proofs occurred. Transitive Rust/npm dependencies remain locked in their existing lockfiles; this inventory is scoped to bundled TLSNotary and Noir source, not a claim to have audited every downloaded build dependency.

## Later-version check (no dependency change)

`licenses/later-version-comparison.json` records exact commit IDs, public source/archive digests, every old/new `.nr` file digest, and copies/digests of later license texts.

- keccak256 current main `3a81a0e3ba7167c65536e9aa9a9500d570d2d3e3` has Apache-2.0 text, but `src/keccak256.nr` and tests have changed from v0.1.1. Subsequent release tags v0.1.2 and v0.1.3 still have no license file.
- sha256 current main `50f5fda729d94848aabcd9d54dc7751460e9143a` has Apache-2.0 text, but SHA-224/SHA-256 algorithm/type files differ from v0.2.1. The subsequent release tag v0.3.0 still has no license file.
- nodash current main / v0.46.0 `55b664ea25b151b286fd50f5a64e9c42d91c677c` still has no license declaration/text and its source differs from v0.42.0.

No inspected candidate permits a license-only substitution over byte-identical old algorithm sources. The inspection covers those current heads and release tags, not every intermediate historical commit. Later license copies in `licenses/later-upstream/` are comparison evidence only; they are not asserted to authorize the old versions. The three exact-version limitations on distributing the full dependency closure remain unresolved.
