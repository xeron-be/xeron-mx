#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
work="$(mktemp -d)"
compose() { docker compose -f compose.yaml "$@"; }
api="http://127.0.0.1:8088/api/v1"
count=20

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'DRILL FAILED: %s\n' "$*" >&2; compose logs --tail 80 >&2 || true; exit 1; }

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

wait_for() {
  local what="$1" tries="$2"
  shift 2
  for _ in $(seq 1 "$tries"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "timed out waiting for $what"
}

call() {
  local method="$1" path="$2" body="${3:-}"
  curl -sf -X "$method" -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    ${body:+-d "$body"} "$api$path"
}

primary_state() { call GET /domains | python3 -c 'import json,sys; print(json.load(sys.stdin)["domains"][0]["primary"]["is_up"])'; }
pending() { call GET /status | python3 -c 'import json,sys; print(json.load(sys.stdin)["queue"]["pending"])'; }

step "start the primary (Postfix) and XeronMX"
compose up -d --build --quiet-pull
wait_for "the XeronMX API" 60 curl -sf "$api/setup"

step "create the admin, a token and the domain"
password="drill-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -sf -c "$work/jar" -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@example.test\",\"password\":\"$password\"}" "$api/setup" >/dev/null
token="$(curl -sf -b "$work/jar" -H "Content-Type: application/json" -d '{"name":"drill","role":"admin"}' \
  "$api/tokens" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"])')"
call POST /domains '{"name":"example.test","primary_host":"mailhost","primary_port":25,"primary_tls":"none"}' >/dev/null
export -f call primary_state pending
export api token
wait_for "the primary to be seen up" 30 bash -c '[ "$(primary_state)" = True ]'

step "take the primary down"
compose stop mailhost
wait_for "the primary to be seen down" 30 bash -c '[ "$(primary_state)" = False ]'

step "send $count messages and a 25 MB attachment while it is down"
for i in $(seq -w 1 "$count"); do
  head -c 2000 /dev/urandom | base64 > "$work/body-$i"
  swaks --silent 2 --server 127.0.0.1 --port 2525 --from "sender$i@elsewhere.test" --to alice@example.test \
    --header "Subject: drill-$i" --body "@$work/body-$i" || fail "message $i was refused"
done
head -c 25000000 /dev/urandom > "$work/big.bin"
swaks --silent 2 --server 127.0.0.1 --port 2525 --from big@elsewhere.test --to bob@example.test \
  --header "Subject: drill-big" --attach-type application/octet-stream --attach-name big.bin \
  --attach "@$work/big.bin" || fail "the large message was refused"
[ "$(pending)" = "$((count + 1))" ] || fail "expected $((count + 1)) held messages, found $(pending)"

step "kill -9 XeronMX with the queue full, then start it again"
compose kill -s KILL xeronmx
compose start xeronmx
wait_for "the XeronMX API after the crash" 60 curl -sf "$api/setup"
[ "$(pending)" = "$((count + 1))" ] || fail "the crash lost messages: $(pending) held"

step "bring the primary back and kill -9 XeronMX again while it delivers"
compose start mailhost
wait_for "a first delivery" 60 bash -c '[ "$(pending)" -lt '"$((count + 1))"' ]'
compose kill -s KILL xeronmx
compose start xeronmx
wait_for "the XeronMX API after the second crash" 60 curl -sf "$api/setup"
wait_for "the queue to drain" 180 bash -c '[ "$(pending)" = 0 ]'

step "check every message arrived intact"
compose exec -T mailhost sh -c 'for f in /home/alice/Maildir/new/* /home/bob/Maildir/new/*; do printf "%s\0" "$f"; cat "$f"; printf "\0"; done' > "$work/mailboxes"
python3 - "$work" "$count" <<'EOF'
import email, hashlib, os, sys
from email import policy

work, count = sys.argv[1], int(sys.argv[2])
raw = open(os.path.join(work, "mailboxes"), "rb").read().split(b"\0")
messages = [email.message_from_bytes(raw[i + 1], policy=policy.compat32) for i in range(0, len(raw) - 1, 2)]
seen = {}
for m in messages:
    seen.setdefault(m["Subject"], []).append(m)

problems = []
for i in range(1, count + 1):
    subject = "drill-%02d" % i
    copies = seen.get(subject, [])
    if not copies:
        problems.append(subject + " is missing")
        continue
    want = open(os.path.join(work, "body-%02d" % i), "rb").read().replace(b"\n", b"\r\n").strip()
    got = copies[0].get_payload(decode=True).replace(b"\n", b"\r\n").strip()
    if got != want:
        problems.append(subject + " arrived altered")
    if not copies[0]["Received"] or "XeronMX" not in " ".join(copies[0].get_all("Received")):
        problems.append(subject + " has no Received header from XeronMX")

big = seen.get("drill-big", [])
if not big:
    problems.append("drill-big is missing")
else:
    for part in big[0].walk():
        if part.get_filename() == "big.bin":
            want = hashlib.sha256(open(os.path.join(work, "big.bin"), "rb").read()).hexdigest()
            if hashlib.sha256(part.get_payload(decode=True)).hexdigest() != want:
                problems.append("drill-big arrived altered")

duplicates = sum(len(v) - 1 for v in seen.values())
print("messages at the primary: %d, distinct: %d, duplicates: %d" % (len(messages), len(seen), duplicates))
if problems:
    print("\n".join(problems))
    sys.exit(1)
EOF

printf '\nDRILL PASSED\n'
