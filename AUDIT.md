# Development review notes

The inherited implementation includes fixes for these issues found during limited AI code review and synthetic testing:

- A proof-supplied JWKS cache must not become an official trust anchor. Official verification fetches public keys from a fixed upstream HTTPS endpoint and rejects an ambiguous or absent key.
- An accepted source release must bind its source, dependency locks, compiled bytecode, and rebuilt verification key. A publisher-supplied manifest cannot authenticate itself.
- Security checks use explicit failures instead of assertions that disappear under Python optimization.
- Public dependency archives and CRS parameters are checked against locked hashes.
- The request challenge is restricted to 64 lowercase hexadecimal characters, and insecure ideal-VM builds are rejected.
- The V2 response-privacy circuit binds authenticated received commitments, field order, length, count, and allowed ASCII characters. It rejects structure-spanning, escaped, wrong-length, and wrong-commitment metadata witnesses.
- The SSH interface pins a separately trusted host key, uses a fixed administrator command, restricts framing, and rejects a wrong host key before starting a credential provider.

The initial fork phase preserved cryptographic source and historical manifests. Later release preparation added root build/review/runtime gates and recalculated both source-file baselines for this new candidate, preserving the historical circuit bytecode/VK identities. This maintainer-generated baseline is not external review. Any synthetic receipts present in a local development tree are historical unless separately regenerated; runtime outputs and compiled artifacts are excluded from the distributed source archive. See any supplied VALIDATION.md for this release's executed checks and limitations.

Open work includes external review of the fixed release, underlying cryptographic libraries, JSON edge cases, side channels, secret memory handling, separate-machine SSH, real V2 upstream compatibility, load, failure presentation, and eventual deployment policy. The vendored upstream library remains experimental. See HISTORICAL_RESULTS.md for the precise V1/V2 boundary.
