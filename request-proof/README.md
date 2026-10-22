# Interactive request-proof experiment (V2)

完整中文入口、固定工具链和当前复核命令见[根 README](../README.md)；给用户自己 AI 的审查提示见[AI_REVIEW](../AI_REVIEW.md)。下文保留实验结构说明，构建与验证请优先使用根目录 `review.py` 的检查入口。

This is a source-review experiment. A user-run verifier joins an actual TLS + MPC-TLS session and binds a fresh challenge, selected request body/model, hidden signed credential, matching account header, and authenticated response. It does not treat a site-written verified flag or a signed application log as upstream evidence.

V2 adds constrained hiding of selected response metadata and an SSH/stdio interface. V2 has only synthetic local TLS and local SSH development results; it has not been deployed, exercised across two machines, or retested using a real upstream account. The V1 real-request result is a de-identified historical statement only, not an offline-verifiable artifact in this fork. See ../HISTORICAL_RESULTS.md.

## Source and trust

- client/src/main.rs, privacy.rs, and transport.rs implement the request binding, response view, and transport.
- circuit/src/main.nr binds the signed credential and authenticated commitments. The response view replaces supported metadata value bytes only under the circuit constraints.
- ../zk-prototype/request_bridge.mjs supplies the proof bridge. Versions and public source/CRS hashes are locked.
- reviewed-build.json retains the historical circuit bytecode/VK identities. Release preparation recalculates its source-file hashes for the new candidate; this is maintainer baseline generation, not external review. Independently accept a reviewed release hash before building or running a verifier. A manifest supplied by an untrusted publisher cannot authenticate itself, and reviewers must not regenerate it to hide a mismatch.

The real mode uses a fixed upstream host/path, validates its certificate, fetches public keys directly, requires HTTP 200 and a completed matching-model response, and rejects unsupported input or oversized data. Known metadata privacy does not guarantee automatic hiding of future fields. The receipt hash covers the authenticated redacted view, not the original upstream response.

## Synthetic reproduction after release review

Use the root python -B review.py build/runtime/reproduce/audit commands after independently reviewing the release. The inherited setup.py is an internal build component, not a substitute for the root installation/runtime gate. See the root README and any supplied VALIDATION.md for executed checks and limits.

The synthetic fixtures are python -B fixture_trial.py and its --wrong-model, --changed-body, --wrong-account, --large-fixture, --ssh, and --bad-host-key modes. Credentials and private fixture keys are generated locally at runtime; real upstream credentials are not needed. Every accepted synthetic result must remain synthetic_only:true and official_openai_request_verified:false.

Requirements from the inherited experiment: Rust 1.95, Node.js 24, Python 3.12, requests, cryptography, and paramiko for the local SSH fixture; OpenSSH is needed for SSH. PROOF_PYTHON can select the Python interpreter. Large public CRS .dat files, build outputs, and node_modules are intentionally absent.

## Limits

The prototype accepts only a restricted Responses request, at most 1024 request-body bytes, 4096 sent bytes, and 65536 received bytes. Known metadata hiding is limited to eight groups of 384 printable ASCII bytes with additional exclusions. The verifier time window is 120 seconds and the process budget is 180 seconds. Unsupported traffic fails instead of silently falling back. These are experimental limits, not production performance commitments.

The vendored TLSNotary commit is 9a3d73c5bdeeab0255bdb05c89116554cebf6dbe. Published upstream static private-key fixtures and every .pem file were omitted. The main release client does not depend on the fixture-server crates; upstream workspace tests/examples may require regenerating omitted fixtures. See ../FORK_REPORT.md for the exact paths and static dependency evidence. The custom synthetic fixture generates its own keys.

A successful request proves that one interaction under the accepted implementation. It does not prove subscription payment/current state, model weights, the entire account pool, or production coverage. This experiment is not an external security audit or upstream endorsement. SSH policy and deployment boundaries are described in CLIENT_SERVER.md.
