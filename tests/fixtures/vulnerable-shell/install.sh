#!/bin/bash
# Intentionally insecure shell script — fixture for shell-runner / shellcheck.
# Carries multiple SCxxxx findings:
#   SC2148 (no shebang on line 1 — not applicable here, fixture HAS shebang;
#           covered indirectly by other rules)
#   SC2086 (unquoted variable in command position)
#   SC2046 (unquoted command substitution)
#   SC2129 (predictable temp file via $$)
#   SC2162 (read without -r)
#   SC2156 (find -exec sh -c with {} interpolated)
#   SC2038 (find pipe to xargs without -print0)

# missing: set -euo pipefail (script-hardening pattern)

tmpfile=/tmp/install-$$
echo "writing to $tmpfile"

read user
echo "user: $user"

target=$1
rm -rf $target/*

cd $(git rev-parse --show-toplevel)

find . -name '*.bak' | xargs rm

find . -name '*.tmp' -exec sh -c 'rm $0' {} \;

curl -sSL https://example.com/installer | bash

eval "$user"
