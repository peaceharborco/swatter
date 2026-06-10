#!/usr/bin/env bash
# install/swatter-deploy-cf-creds.sh — deploy Cloudflare creds + domain map to a
# Swatter server, from your workstation, without committing any secret.
#
# Mirrors the "fetch locally, scp, chown root-only" pattern used for other
# server secrets: the workstation holds the credentials (a creds file you build
# however you like — e.g. from a password manager), and only a minimal-scope
# token ever lands on the server. No password-manager agent or runtime secret
# fetch is required ON the server.
#
# Inputs:
#   --creds   <file>   lines "account<TAB>token" (one per CF account). 0600 here.
#   --domains <file>   a cf-domains.conf-style file: "domain  profile  [account]"
#                      (account defaults to the value of --default-account;
#                      rows whose profile is "skip" are omitted from the map).
#   --host    <ssh>    ssh destination (e.g. root@server or an ssh alias).
#   --default-account <name>   account name for rows with no 3rd column (def: peaceharbor)
#
# Deploys:
#   /etc/swatter/cloudflare.creds   (0600 root:root)  account<TAB>token
#   /etc/swatter/cf-domains.map     (0644 root:root)  domain<TAB>account
#
# Tokens need only the Cloudflare "Firewall Services: Edit" permission (zone IP
# Access Rules) for the account's zones — nothing else.

set -euo pipefail

CREDS="" DOMAINS="" HOST="" DEFACCT="peaceharbor"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --creds)           CREDS="$2"; shift 2 ;;
        --domains)         DOMAINS="$2"; shift 2 ;;
        --host)            HOST="$2"; shift 2 ;;
        --default-account) DEFACCT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
[[ -n "$CREDS" && -n "$DOMAINS" && -n "$HOST" ]] || {
    echo "usage: $0 --creds <file> --domains <cf-domains.conf> --host <ssh> [--default-account peaceharbor]" >&2
    exit 2
}
[[ -r "$CREDS" ]]   || { echo "creds file not readable: $CREDS" >&2; exit 1; }
[[ -r "$DOMAINS" ]] || { echo "domains file not readable: $DOMAINS" >&2; exit 1; }

# Build the domain->account map (skip blank/comment/skip-profile rows).
map="$(mktemp "${TMPDIR:-/tmp}/swatter-cf-map.XXXXXX")"
trap 'rm -f "$map"' EXIT
awk -v def="$DEFACCT" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
        domain=$1; profile=$2; acct=$3
        if (profile == "skip") next
        if (acct == "") acct=def
        print domain "\t" acct
    }' "$DOMAINS" > "$map"

ndoms="$(wc -l < "$map" | tr -d ' ')"
ncreds="$(grep -cvE '^[[:space:]]*(#|$)' "$CREDS" | tr -d ' ')"
echo "Deploying ${ncreds} account token(s) and ${ndoms} domain mapping(s) to ${HOST} ..."

ssh "$HOST" 'mkdir -p /etc/swatter'
scp -q "$CREDS" "${HOST}:/etc/swatter/cloudflare.creds"
scp -q "$map"   "${HOST}:/etc/swatter/cf-domains.map"
ssh "$HOST" 'chown root:root /etc/swatter/cloudflare.creds /etc/swatter/cf-domains.map
             chmod 0600 /etc/swatter/cloudflare.creds
             chmod 0644 /etc/swatter/cf-domains.map'

echo "Deployed. Verifying on ${HOST}:"
ssh "$HOST" '/usr/local/bin/swatter test-config | grep -iE "CF creds|CF domain|CF action|mode:"'
echo "Done. A dry-run will now show 'cloudflare block ... in <domain>' for proxied offenders."
