#!/bin/sh
# Operator-owned forced command. This example is NOT installed by setup.py.
# No client-supplied command, environment script or production key is evaluated.
set -eu
export PATH=/usr/local/bin:/usr/bin:/bin
export PROOF_PYTHON=/usr/bin/python3
exec /opt/tokenford-proof/request-proof/client/target/release/tokenford-user-verifier-prototype \
  serve-stdio /etc/tokenford-proof/policy.json
