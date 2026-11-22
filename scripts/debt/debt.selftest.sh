#!/usr/bin/env bash
# scripts/debt/debt.selftest.sh — battery for `ehs debt` (scripts/debt/ehs_debt.py).
#
# WHAT IT PROVES
#   K3  every probe fires on its vulnerable fixture and stays silent on the safe twin
#   K4  no planted secret value and no row of data ever reaches the output
#   W4  the scope guard: remote targets refused, the network probe refused without an
#       ownership attestation and for a host the repository never references
#   and that the ledger moves open -> closed -> regression_detected, and that a probe
#   which did not run closes nothing.
#
# WHY THE FIXTURES ARE BUILT HERE AND NOT CHECKED IN
#   A checked-in fixture holding a secret-shaped string is exactly what G6
#   (gate-secret-scan.sh) exists to fail. The strings are assembled at run time from
#   pieces, so the tree never holds one.
#
# Exit codes: 0 = behaved | 1 = did not | 2 = could not measure (no python3)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEBT="$HERE/ehs-debt"
command -v python3 >/dev/null 2>&1 || { echo "COULD NOT MEASURE: python3 missing"; exit 2; }
W="$(mktemp -d 2>/dev/null || mktemp -d -t ehsdebt)"; trap 'rm -rf "$W"; [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null' EXIT
pass=0; fail=0
ok()  { printf 'PASS  %s\n' "$1"; pass=$((pass+1)); }
bad() { printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -8 | sed 's/^/      /'; fail=$((fail+1)); }

python3 - "$W" <<'PY'
import sys, base64, json
from pathlib import Path
w = Path(sys.argv[1])
def put(rel, text):
    p = w / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
SK = "sk" + "-proj-" + "Q7x" * 9                       # openai-shaped, assembled
SR = "eyJ" + b64({"alg": "HS256"})[3:] + "." + b64({"role": "service_" + "role", "iss": "supabase"}) + "." + "s1g" * 8
AN = "eyJ" + b64({"alg": "HS256"})[3:] + "." + b64({"role": "anon", "iss": "supabase"}) + "." + "a9n" * 8
(w / "planted.txt").write_text("\n".join([SK, SR]))
# --- vulnerable app
v = "vuln"
put(f"{v}/web/src/main.js", f"const client = createClient(URL, '{SR}');\nconst k = '{SK}';\n")
put(f"{v}/web/vite.config.js", "export default {}\n")
put(f"{v}/web/.env.local", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=abc\n")
put(f"{v}/supabase/migrations/001.sql",
    "create table public.notes (id int);\ncreate table public.orders (id int);\n"
    "alter table public.orders enable row level security;\n"
    "create policy \"all\" on public.orders for update using (true);\n")
put(f"{v}/firebase/firestore.rules", "service cloud.firestore {\n match /{d=**} { allow read, write: if true; }\n}\n")
put(f"{v}/api/auth.py",
    "import hashlib, random, requests, jwt\n"
    "def save(password):\n    return hashlib.md5(password.encode()).hexdigest()\n"
    "def login(user, password):\n    if user.password == password:\n        return True\n"
    "reset_token = random.randint(100000, 999999)\n"
    "r = requests.get(URL, verify=False)\n"
    "tok = jwt.encode({'a': 1}, 'secret', algorithm='HS256')\n"
    "cur.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n"
    "print('login', password)\n"
    "app.run(debug=True)\n")
put(f"{v}/api/crypto.js", "const c = crypto.createCipher('aes-256-cbc', key);\nconst t = jwt.decode(token);\n")
put(f"{v}/.mcp.json", json.dumps({"mcpServers": {"db": {"command": "npx", "args": ["-y", "some-mcp"],
                                  "env": {"DB_TOKEN": SK}}}}))
put(f"{v}/package.json", json.dumps({"dependencies": {"left-pad": "*"}}))
# --- safe twin: same shapes, done right
s = "safe"
put(f"{s}/web/src/main.js", f"const client = createClient(import.meta.env.VITE_SUPABASE_URL, '{AN}');\n")
put(f"{s}/web/vite.config.js", "export default {}\n")
put(f"{s}/web/.env.local", "VITE_SUPABASE_ANON_KEY=abc\n")
put(f"{s}/supabase/migrations/001.sql",
    "create table public.notes (id int, owner uuid);\nalter table public.notes enable row level security;\n"
    "create policy \"own\" on public.notes for all using (auth.uid() = owner);\n")
put(f"{s}/firebase/firestore.rules", "service cloud.firestore {\n match /u/{id} { allow read, write: if request.auth.uid == id; }\n}\n")
put(f"{s}/api/auth.py",
    "import os, secrets, requests, jwt\nfrom argon2 import PasswordHasher\n"
    "def save(password):\n    return PasswordHasher().hash(password)\n"
    "reset_token = secrets.token_urlsafe(32)\n"
    "r = requests.get(URL, timeout=5)\n"
    "tok = jwt.encode({'a': 1}, os.environ['JWT_SECRET'], algorithm='HS256')\n"
    "cur.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n"
    "print('Invalid password')\n"
    "app.run(debug=os.environ.get('DEBUG') == '1')\n")
put(f"{s}/api/crypto.js", "const c = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));\n"
    "const t = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });\n")
put(f"{s}/.mcp.json", json.dumps({"mcpServers": {"db": {"command": "npx", "args": ["-y", "some-mcp@1.2.3"],
                                  "env": {"DB_TOKEN": "${DB_TOKEN}"}}}}))
put(f"{s}/package.json", json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
put(f"{s}/package-lock.json", "{}")
put(f"{s}/.gitignore", ".env\n")
put(f"{s}/.env", f"OPENAI_API_KEY={SK}\n")   # ignored by .gitignore: the right practice, not debt
PY

echo "=== self-test: ehs debt ==="
VOUT="$("$DEBT" scan "$W/vuln" --format json 2>&1)"; vrc=$?
SOUT="$("$DEBT" scan "$W/safe" --format json 2>&1)"; src=$?
[ "$vrc" -eq 1 ] && ok "vulnerable app exits 1" || bad "vulnerable app exits 1 (rc=$vrc)" "$VOUT"
for c in DEBT-01 DEBT-02 DEBT-03 DEBT-04 DEBT-05 DEBT-06 DEBT-07 DEBT-08 DEBT-09 DEBT-10 DEBT-11 DEBT-12 DEBT-13; do
  n="$(printf '%s' "$VOUT" | python3 -c "import json,sys;print(sum(f['class']=='$c' for f in json.load(sys.stdin)['findings']))" 2>/dev/null || echo ERR)"
  m="$(printf '%s' "$SOUT" | python3 -c "import json,sys;print(sum(f['class']=='$c' and f['severity']!='low' for f in json.load(sys.stdin)['findings']))" 2>/dev/null || echo ERR)"
  [ "$n" != ERR ] && [ "$n" -ge 1 ] && ok "$c fires on the vulnerable fixture ($n)" || bad "$c fires on the vulnerable fixture ($n)"
  [ "$m" = 0 ] && ok "$c silent (>= medium) on the safe twin" || bad "$c silent (>= medium) on the safe twin ($m)" "$(printf '%s' "$SOUT" | grep -A3 "\"$c\"")"
done
[ "$src" -eq 0 ] && ok "safe twin exits 0" || bad "safe twin exits 0 (rc=$src)"

# K4: no planted value in any output, text or json
leak=0
while IFS= read -r sec; do
  [ -z "$sec" ] && continue
  for o in "$VOUT" "$("$DEBT" scan "$W/vuln" 2>&1)" "$SOUT"; do
    printf '%s' "$o" | grep -qF -- "$sec" && leak=1
  done
done < "$W/planted.txt"
[ "$leak" -eq 0 ] && ok "no planted secret value reaches the output" || bad "a planted secret value reached the output"

# W4: scope guard
for t in "https://example.org/r.git" "git@example.org:o/r.git" "ssh://example.org/r" "$W/does-not-exist"; do
  "$DEBT" scan "$t" >/dev/null 2>&1; rc=$?
  [ "$rc" -eq 2 ] && ok "refuses target '$t'" || bad "refuses target '$t' (rc=$rc)"
done
ln -s /etc "$W/vuln/escape" 2>/dev/null
"$DEBT" scan "$W/vuln" --format json 2>/dev/null | grep -q '"file": "escape/' \
  && bad "a symlink out of the target was followed" || ok "a symlink out of the target is not followed"

# ledger: open -> closed -> regression_detected; an unrun probe closes nothing
L="$W/led"; mkdir -p "$L/api"
printf 'import requests\nr = requests.get(U, verify=False)\n' > "$L/api/a.py"
"$DEBT" scan "$L" --ledger >/dev/null 2>&1
st() { python3 -c "import json;d=json.load(open('$L/.ehs/debt.json'));print(','.join(sorted(i['status'] for i in d['items'].values())))"; }
[ "$(st)" = "open" ] && ok "ledger records an open item" || bad "ledger records an open item ($(st))"
printf 'import requests\nr = requests.get(U, timeout=5)\n' > "$L/api/a.py"
"$DEBT" scan "$L" --ledger >/dev/null 2>&1
[ "$(st)" = "closed" ] && ok "ledger closes it when the probe stops seeing it" || bad "ledger closes it ($(st))"
python3 -c "import json;d=json.load(open('$L/.ehs/debt.json'));i=list(d['items'].values())[0];assert 'not verified' in i['closed_means']" \
  && ok "closed says 'not verified fixed'" || bad "closed says 'not verified fixed'"
printf 'import requests\nr = requests.get(U, verify=False)\n' > "$L/api/a.py"
"$DEBT" scan "$L" --ledger >/dev/null 2>&1
[ "$(st)" = "regression_detected" ] && ok "a closed item that returns is a regression" || bad "regression detected ($(st))"
M="$W/mcp"; mkdir -p "$M"; printf '{"mcpServers":{"a":{"command":"x","args":["-y","pkg"]}}}' > "$M/.mcp.json"
"$DEBT" scan "$M" --ledger >/dev/null 2>&1; rm "$M/.mcp.json"; "$DEBT" scan "$M" --ledger >/dev/null 2>&1
python3 -c "import json;d=json.load(open('$M/.ehs/debt.json'));assert all(i['status']=='open' for i in d['items'].values()), d" \
  && ok "a probe with no input closes nothing" || bad "a probe with no input closes nothing"

# network probe: refused without attestation, refused for an unreferenced host, never prints a row
N="$W/net"; mkdir -p "$N/web"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
AN="$(python3 -c "import base64,json;b=lambda d:base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip('=');print('eyJ'+b({'alg':'HS256'})[3:]+'.'+b({'role':'anon'})+'.'+'z9z'*8)")"
printf "const s = createClient('http://127.0.0.1:%s', '%s');\nconst r = await s.from('notes').select();\n" "$PORT" "$AN" > "$N/web/app.js"
"$DEBT" scan "$N" --network >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && ok "network probe refused without an attestation" || bad "network probe refused without an attestation (rc=$rc)"
"$DEBT" init "$N" --owner tester --host other.example.org --i-own-this >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && ok "init refuses a host the repository never references" || bad "init refuses an unreferenced host (rc=$rc)"
"$DEBT" init "$N" --owner tester --host 127.0.0.1 >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && ok "init refuses without --i-own-this" || bad "init refuses without --i-own-this (rc=$rc)"
python3 -I - "$PORT" >/dev/null 2>&1 <<'PY' &
import sys, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'[{"email":"ROW-CONTENT-MARKER"}]'
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
SRV=$!; sleep 1
"$DEBT" init "$N" --owner tester --host 127.0.0.1 --i-own-this >/dev/null 2>&1
NOUT="$("$DEBT" scan "$N" --network 2>&1)"
printf '%s' "$NOUT" | grep -q "DEBT-N1.*1 open" && ok "network probe reports an anonymous read" || bad "network probe reports an anonymous read" "$NOUT"
printf '%s' "$NOUT" | grep -q "ROW-CONTENT-MARKER" && bad "network probe printed row content" || ok "network probe never prints row content"
printf '%s' "$NOUT" | grep -qF -- "$AN" && bad "network probe printed the key" || ok "network probe never prints the key"

echo
echo "$pass PASS / $fail FAIL"
[ "$fail" -eq 0 ] || exit 1
exit 0
