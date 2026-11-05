#!/usr/bin/env bash
# Runs ON the server (root). Prints the A records a hostname really has,
# querying the zone's authoritative nameservers directly.
#
#   resolve-auth.sh <hostname>
#
# Why not getent/dig without an explicit server? This box's /etc/hosts maps
# `example.com` to 127.0.0.1, so glibc derives a search domain of `com` and
# resolves `mail.example.com.com` instead — which Cloudflare happily answers.
# Recursive resolvers also hold NXDOMAIN for the SOA minimum, so a brand-new
# record can look missing for up to half an hour.
set -uo pipefail

NAME=${1:?hostname}
NAME=${NAME%.}          # never allow a double trailing dot

# Walk up the labels until a suffix answers NS. For mail.example.com that is
# example.com; querying the full name would just return NOERROR/empty.
ZONE=""
labels=(${NAME//./ })
for ((i = 0; i < ${#labels[@]} - 1; i++)); do
  candidate=$(IFS=.; echo "${labels[*]:i}")
  for resolver in 1.1.1.1 9.9.9.9 8.8.8.8; do
    if dig +short +time=3 +tries=1 NS "${candidate}" @"${resolver}" 2>/dev/null | grep -q '\.'; then
      ZONE=$candidate
      break 2
    fi
  done
done

if [ -z "$ZONE" ]; then
  echo "ERROR: could not find the authoritative zone for $NAME" >&2
  exit 2
fi

mapfile -t AUTH < <(
  for resolver in 1.1.1.1 9.9.9.9 8.8.8.8; do
    dig +short +time=3 +tries=1 NS "${ZONE}" @"${resolver}" 2>/dev/null
  done | sed 's/\.$//' | sort -u
)

if [ "${#AUTH[@]}" -eq 0 ]; then
  echo "ERROR: no authoritative nameservers for $ZONE" >&2
  exit 2
fi

ANSWERED=0
FOUND=()
for ns in "${AUTH[@]}"; do
  mapfile -t ANSWERS < <(dig +short +time=3 +tries=1 A "${NAME}." @"$ns" 2>/dev/null)
  if [ "${#ANSWERS[@]}" -gt 0 ]; then
    ANSWERED=1
    FOUND+=("${ANSWERS[@]}")
  fi
done

IPS=$(printf '%s\n' "${FOUND[@]}" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
if [ -z "$IPS" ]; then
  # Distinguish "authoritative servers all say no" from "we could not ask".
  [ "$ANSWERED" = "1" ] || { echo "ERROR: no authoritative server answered for $NAME" >&2; exit 2; }
  echo "MISSING"
  exit 0
fi

printf '%s\n' "$IPS"
