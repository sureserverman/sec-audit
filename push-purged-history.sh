#!/usr/bin/env bash
#
# Push the four security-fixed repos to origin.
#
# Three of them (nice-dns, tor-haproxy, tor-socat) had their history rewritten
# by git-filter-repo. We:
#   - fetch origin first so --force-with-lease has refs to compare against,
#   - force-with-lease for branches (lease catches concurrent pushes),
#   - plain --force for tags (lease has no anchor for tags — refs/remotes/
#     origin/tags/* doesn't exist; "stale info" is the usual symptom).
#
# Safe to re-run — already-pushed refs become no-ops.
#
# Run from VSCode's integrated terminal (which has GitHub credentials).

set -euo pipefail

for repo in nice-dns tor-haproxy tor-socat; do
    cd "/home/user/dev/$repo"
    echo "=== $repo (force-push) ==="
    git remote add origin "https://github.com/sureserverman/$repo.git" 2>/dev/null \
        || git remote set-url origin "https://github.com/sureserverman/$repo.git"
    # Populate refs/remotes/origin/* so --force-with-lease has anchors for branches.
    git fetch origin --quiet
    git push --force-with-lease --all origin
    # Tags: --force (the lease has no remote-tracking ref to compare against).
    git push --force --tags origin
    echo "✓ $repo pushed"
    echo
done

cd /home/user/dev/hardened-unbound
echo "=== hardened-unbound (normal push) ==="
git push origin
git push origin --tags
echo "✓ hardened-unbound pushed"

echo
echo "All four repos pushed."
