#!/usr/bin/env bash
# Ask Vercel to rebuild the site after a new status.json was published.
#
# Waits until raw.githubusercontent.com serves the status document for the
# expected commit (its CDN caches for up to five minutes), so the rebuild
# reads the new data, then POSTs to the deploy hook. Without a hook URL the
# script prints a notice and exits 0.
#
# Environment:
#   VERCEL_DEPLOY_HOOK  deploy hook URL (repository secret); optional
#   SITE_STATUS_URL     status URL the site reads (default: the site-data branch)
#   EXPECT_COMMIT       commit the status must show (default: commit in build/status.json)
set -euo pipefail

if [ -z "${VERCEL_DEPLOY_HOOK:-}" ]; then
  echo "trigger-site-deploy: VERCEL_DEPLOY_HOOK is not set; skipping the redeploy"
  exit 0
fi
url=${SITE_STATUS_URL:-https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/site-data/status.json}
want=${EXPECT_COMMIT:-$(jq -r .commit build/status.json 2>/dev/null || true)}

if [ -n "$want" ]; then
  for _ in $(seq 1 40); do
    got=$(curl -fsS --max-time 10 "$url" | jq -r .commit 2>/dev/null || true)
    if [ "$got" = "$want" ]; then
      echo "trigger-site-deploy: $url serves commit $want"
      break
    fi
    sleep 10
  done
  [ "${got:-}" = "$want" ] || echo "trigger-site-deploy: $url still serves ${got:-nothing} after 400 s; redeploying anyway"
fi

curl -fsS --max-time 30 -X POST "$VERCEL_DEPLOY_HOOK" -o /dev/null
echo "trigger-site-deploy: redeploy requested"
