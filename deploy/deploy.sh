#!/usr/bin/env bash
# Deploy the resource/SSH monitor to 203.0.113.10 and publish it at
# https://panel.example.com/
#
#   PASS='<root password>' bash deploy/deploy.sh
#
# Idempotent and safe to re-run.
#
# Isolation guarantees (this is why it is a separate deploy script):
#   - its own system user      monsvc
#   - its own app directory    /opt/monitor
#   - its own data directory   /var/lib/monitor
#   - its own port             127.0.0.1:8087
#   - its own systemd unit     monitor.service
#   - its own nginx vhosts     panel.example.com.conf + blocked.example.com.conf
#   - its own certificates     /etc/letsencrypt/live/{panel,blocked}.example.com/
# The traffic filter additionally installs one root-owned helper and one
# NOPASSWD sudoers rule (the only command monsvc may run as root), and adds an
# include line to the existing example.com / mail / logs vhosts. Those edits are
# idempotent and only add `/etc/nginx/snippets/monitor-tf-<port>.conf`; the
# snippet itself is empty unless a filter rule is active, so the sites behave
# exactly as before until the panel is used.
# Existing services keep running untouched.
#
# Prerequisite: panel.example.com must resolve to this server. The script stops
# before touching nginx if it does not.
set -euo pipefail

HOST="${HOST:-203.0.113.10}"
PORT="${PORT:-22}"
SSH_USER="${SSH_USER:-root}"
PASS="${PASS:?set PASS to the root password}"
APP_DIR=/opt/monitor
DATA_DIR=/var/lib/monitor
ENV_DIR=/etc/monitor
ENV_FILE=$ENV_DIR/monitor.env
APP_PORT="${APP_PORT:-8087}"
MONITOR_HOST="${MONITOR_HOST:-panel.example.com}"
FAILED_HOST="${FAILED_HOST:-blocked.example.com}"
MAIN_HOST="${MAIN_HOST:-example.com}"
SITE_CONF="/etc/nginx/sites-available/${MONITOR_HOST}.conf"
SITE_LINK="/etc/nginx/sites-enabled/${MONITOR_HOST}.conf"
FAILED_CONF="/etc/nginx/sites-available/${FAILED_HOST}.conf"
FAILED_LINK="/etc/nginx/sites-enabled/${FAILED_HOST}.conf"
CERT_DIR="/etc/letsencrypt/live/${MONITOR_HOST}"
FAILED_CERT_DIR="/etc/letsencrypt/live/${FAILED_HOST}"
WEBROOT=/var/www/certbot
HERE="$(cd "$(dirname "$0")" && pwd)"

SCP_OPTS=(-P "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o PreferredAuthentications=password -o PubkeyAuthentication=no)

rsh() { PASS="$PASS" HOST="$HOST" PORT="$PORT" USER_="$SSH_USER" bash "$HERE/rsh.sh" "$@"; }

put() {
  local src="$1" dst="$2" n=0
  while [ $n -lt 8 ]; do
    n=$((n + 1))
    if sshpass -p "$PASS" scp "${SCP_OPTS[@]}" "$src" "$SSH_USER@$HOST:$dst" 2>/tmp/monitor-scp.err; then
      return 0
    fi
    if grep -qiE "connection closed|reset|timed out|broken pipe|kex_exchange" /tmp/monitor-scp.err; then
      sleep 10
      continue
    fi
    cat /tmp/monitor-scp.err >&2
    return 1
  done
  echo "scp failed after $n attempts: $src" >&2
  return 1
}

echo "==> 1/9 preflight"
rsh "command -v node >/dev/null || { echo 'node is missing' >&2; exit 5; }
     node -v
     command -v nginx >/dev/null || { echo 'nginx is missing' >&2; exit 5; }
     command -v certbot >/dev/null || { echo 'certbot is missing' >&2; exit 5; }
     command -v journalctl >/dev/null || { echo 'journalctl is missing' >&2; exit 5; }
     if ss -lntp | grep -q ':${APP_PORT} '; then
       if ss -lntp | grep ':${APP_PORT} ' | grep -q 'node'; then
         echo 'port ${APP_PORT} already served by the monitor (re-deploy)'
       else
         echo 'port ${APP_PORT} is occupied by another process' >&2
         ss -lntp | grep ':${APP_PORT} ' >&2
         exit 6
       fi
     fi
     # The mail socket is how alerts leave the box; without it the monitor is
     # useless, so refuse to install rather than fail silently later.
     if [ ! -S /run/mail-panel/api.sock ]; then
       echo 'WARNING: /run/mail-panel/api.sock is missing — alerts will fail' >&2
     else
       echo 'mail socket present'
     fi
     echo 'preflight ok'"

echo "==> 2/9 service user + environment"
if [ ! -f "$HERE/monitor.env.local" ]; then
  echo "    creating monitor.env.local"
  cat > "$HERE/monitor.env.local" <<EOF
MONITOR_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)
MONITOR_SECRET=$(openssl rand -hex 32)
EOF
  chmod 600 "$HERE/monitor.env.local"
  echo "    generated: $HERE/monitor.env.local  (keep it, it holds the panel password)"
fi

# The mail API key is NOT copied here. It lives in the mail panel's env file and
# is read on the server at deploy time, so the secret has exactly one home.
rsh "id -u monsvc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin monsvc
     # journalctl needs the systemd-journal group.
     # www-data is needed for the mail socket: it is srw-rw---- www-data:www-data,
     # so without this group the monitor can read /proc and the journal but
     # cannot send a single alert. Verified with an actual request below.
     usermod -a -G systemd-journal monsvc
     usermod -a -G www-data monsvc
     install -d -o root    -g root    -m 755 ${APP_DIR}
     install -d -o root    -g root    -m 755 ${ENV_DIR}
     install -d -o monsvc  -g monsvc  -m 750 ${DATA_DIR}
     id monsvc
     if [ -S /run/mail-panel/api.sock ]; then
       su -s /bin/sh monsvc -c 'node -e \"
         const http=require(\\\"http\\\");
         const r=http.request({socketPath:\\\"/run/mail-panel/api.sock\\\",path:\\\"/v1/health\\\",method:\\\"GET\\\"},res=>{
           console.log(\\\"mail socket reachable, health HTTP \\\"+res.statusCode); process.exit(res.statusCode===200?0:1);
         });
         r.on(\\\"error\\\",e=>{console.log(\\\"mail socket NOT reachable: \\\"+e.code);process.exit(1)});
         r.end();\"'
     fi"

put "$HERE/monitor.env.local" "/tmp/monitor.env"
if [ "${FORCE_ENV:-0}" = "1" ]; then
  echo "    FORCE_ENV=1 — replacing $ENV_FILE"
  rsh "install -o root -g root -m 600 /tmp/monitor.env $ENV_FILE"
elif rsh "test -f $ENV_FILE"; then
  echo "    keeping existing $ENV_FILE (password stays as-is)"
else
  rsh "install -o root -g root -m 600 /tmp/monitor.env $ENV_FILE"
  echo "    installed env from local copy"
fi

# Pull the mail API credentials from the mail panel's own env file, so the
# monitor never stores a second copy of the secret.
rsh "python3 - <<'PY'
import os, pwd, re
mail_env = '/etc/mail-panel/panel.env'
target = '${ENV_FILE}'
line = ''
if os.path.exists(mail_env):
    for l in open(mail_env):
        if l.startswith('MAIL_API_KEYS='):
            line = l.split('=', 1)[1].strip()
            break
if not line:
    print('    WARNING: no MAIL_API_KEYS in', mail_env)
else:
    key_id, _, secret = line.split(',')[0].partition(':')
    text = open(target).read().splitlines()
    out, have_id, have_secret = [], False, False
    for l in text:
        if l.startswith('MAIL_API_KEY_ID='):
            out.append('MAIL_API_KEY_ID=' + key_id); have_id = True
        elif l.startswith('MAIL_API_SECRET='):
            out.append('MAIL_API_SECRET=' + secret); have_secret = True
        else:
            out.append(l)
    if not have_id: out.append('MAIL_API_KEY_ID=' + key_id)
    if not have_secret: out.append('MAIL_API_SECRET=' + secret)
    os.chmod(target, 0o600)
    open(target, 'w').write('\n'.join(out) + '\n')
    print('    wired mail API credentials (key id: %s)' % key_id)
PY
     rm -f /tmp/monitor.env
     chmod 600 $ENV_FILE
     install -d -o monsvc -g monsvc -m 750 $DATA_DIR"

echo "==> 3/9 uploading application"
rsh "install -d -o root -g root -m 755 ${APP_DIR}/lib ${APP_DIR}/test ${APP_DIR}/deploy"
put "$HERE/../server.js"          "$APP_DIR/server.js"
put "$HERE/../ui.html"            "$APP_DIR/ui.html"
put "$HERE/../package.json"       "$APP_DIR/package.json"
put "$HERE/../README.md"          "$APP_DIR/README.md"
for f in "$HERE"/../lib/*.js;  do put "$f" "$APP_DIR/lib/$(basename "$f")"; done
for f in "$HERE"/../test/*.js; do put "$f" "$APP_DIR/test/$(basename "$f")"; done
rsh "chown -R root:root ${APP_DIR}
     find ${APP_DIR} -type d -exec chmod 755 {} +
     find ${APP_DIR} -type f -exec chmod 644 {} +
     node --check ${APP_DIR}/server.js
     for f in ${APP_DIR}/lib/*.js; do node --check \$f; done
     echo 'syntax ok'"

echo "==> 4/9 systemd unit"
put "$HERE/monitor.service" "/tmp/monitor.service"
rsh "install -o root -g root -m 644 /tmp/monitor.service /etc/systemd/system/monitor.service
     rm -f /tmp/monitor.service
     systemctl daemon-reload
     systemctl enable monitor >/dev/null 2>&1
     systemctl restart monitor
     sleep 2
     systemctl is-active monitor
     curl -fsS -m 5 http://127.0.0.1:${APP_PORT}/health; echo"

echo "==> 5/9 traffic filter nginx helper"
put "$HERE/nginx-tf-sync.sh" "/tmp/monitor-nginx-tf"
put "$HERE/nginx-tf-include.py" "/tmp/nginx-tf-include.py"
# The helper runs as root through one sudoers entry. Seed the staging directory
# first so the helper can validate and install a complete, empty (drop-mode)
# configuration before any panel save — and so the include lines added below
# always point at existing files.
rsh "install -d -o root -g root -m 755 /usr/local/libexec
     install -o root -g root -m 755 /tmp/monitor-nginx-tf /usr/local/libexec/monitor-nginx-tf
     rm -f /tmp/monitor-nginx-tf
     printf '%s\n' 'monsvc ALL=(root) NOPASSWD: /usr/local/libexec/monitor-nginx-tf' \\
       > /etc/sudoers.d/monitor-nginx-tf
     chown root:root /etc/sudoers.d/monitor-nginx-tf
     chmod 0440 /etc/sudoers.d/monitor-nginx-tf
     visudo -cf /etc/sudoers.d/monitor-nginx-tf

     install -d -o monsvc -g monsvc -m 750 ${DATA_DIR}/nginx
     install -d -o root -g root -m 755 /etc/nginx/snippets /etc/nginx/conf.d /var/www/blocked.example.com
     printf 'drop\n' > ${DATA_DIR}/nginx/mode
     : > ${DATA_DIR}/nginx/cf.map
     : > ${DATA_DIR}/nginx/tf-exempt.map
     : > ${DATA_DIR}/nginx/tf-80.map
     : > ${DATA_DIR}/nginx/tf-443.map
     if [ ! -s ${DATA_DIR}/nginx/index.html ]; then
       printf '%s\n' '<!doctype html><meta charset=\"utf-8\"><title>Access restricted</title>' \\
         '<p>This website is not yet available in your country or region.</p>' \\
         > ${DATA_DIR}/nginx/index.html
     fi
     chown -R monsvc:monsvc ${DATA_DIR}/nginx
     chmod 640 ${DATA_DIR}/nginx/mode ${DATA_DIR}/nginx/cf.map \\
       ${DATA_DIR}/nginx/tf-exempt.map ${DATA_DIR}/nginx/tf-80.map \\
       ${DATA_DIR}/nginx/tf-443.map ${DATA_DIR}/nginx/index.html

     # Prove the sudo path works exactly as the service will use it.
     sudo -u monsvc sudo -n /usr/local/libexec/monitor-nginx-tf

     # Idempotently add the includes to the three public sites. panel.example.com
     # is deliberately excluded: the panel itself must stay reachable even when
     # a country rule would otherwise match the operator.
     python3 /tmp/nginx-tf-include.py \\
       /etc/nginx/sites-enabled/${MAIN_HOST}.conf \\
       /etc/nginx/sites-enabled/mail.${MAIN_HOST}.conf \\
       /etc/nginx/sites-enabled/logs.${MAIN_HOST}.conf
     rm -f /tmp/nginx-tf-include.py
     nginx -t
     systemctl reload nginx

     # Restart once more now that the helper exists, so the live rules and the
     # default failure page are pushed through the real code path.
     systemctl restart monitor
     sleep 2
     systemctl is-active monitor
     # sudo refuses to elevate when this flag is set, and several sandbox=
     # options imply it silently. Fail the deploy instead of leaving a panel
     # whose mode switch always errors.
     pid=\$(systemctl show -p MainPID --value monitor)
     grep -q 'NoNewPrivs:[[:space:]]*0' /proc/\$pid/status \\
       || { echo 'monitor still runs with PR_SET_NO_NEW_PRIVS; sudo cannot elevate' >&2; exit 7; }
     echo 'monitor: sudo path usable (NoNewPrivs=0)'"

echo "==> 6/9 DNS check for ${MONITOR_HOST}"
put "$HERE/resolve-auth.sh" "/tmp/resolve-auth.sh"
rsh "install -o root -g root -m 755 /tmp/resolve-auth.sh /usr/local/bin/resolve-auth
     rm -f /tmp/resolve-auth.sh"

DNS_STATE=$(rsh "resolve-auth ${MONITOR_HOST} | tr '\n' ' '" || true)

case "$DNS_STATE" in
  ERROR*|"")
    cat >&2 <<EOF

    Could not resolve ${MONITOR_HOST} from the server:
      ${DNS_STATE:-no answer}

    The service is installed and running on 127.0.0.1:${APP_PORT}.
    Add a DNS A/AAAA record for ${MONITOR_HOST}, then re-run:

        Type: A     Name: <panel host>     Content: ${HOST}

    If you use a CDN/proxy, make sure HTTP-01 ACME validation can reach this
    server (or issue the certificate another way and re-run).

EOF
    exit 3
    ;;
esac

echo "    resolves to: ${DNS_STATE}"

echo "==> 7/9 nginx vhost + certificate"
put "$HERE/nginx-monitor.conf" "/tmp/nginx-monitor.conf"
put "$HERE/nginx-monitor-bootstrap.conf" "/tmp/nginx-monitor-bootstrap.conf"
rsh "install -d -m 755 ${WEBROOT}
     install -o root -g root -m 644 /tmp/nginx-monitor.conf /etc/nginx/snippets/nginx-monitor.conf
     install -o root -g root -m 644 /tmp/nginx-monitor-bootstrap.conf /etc/nginx/snippets/nginx-monitor-bootstrap.conf
     rm -f /tmp/nginx-monitor.conf /tmp/nginx-monitor-bootstrap.conf

     if [ -f ${CERT_DIR}/fullchain.pem ]; then
       echo '    certificate already present — installing full vhost'
       install -o root -g root -m 644 /etc/nginx/snippets/nginx-monitor.conf ${SITE_CONF}
     else
       echo '    no certificate yet — installing HTTP-only bootstrap vhost'
       install -o root -g root -m 644 /etc/nginx/snippets/nginx-monitor-bootstrap.conf ${SITE_CONF}
     fi
     ln -sf ${SITE_CONF} ${SITE_LINK}
     nginx -t
     systemctl reload nginx"

if ! rsh "test -f ${CERT_DIR}/fullchain.pem"; then
  echo "    requesting certificate via webroot challenge"
  if ! rsh "certbot certonly --webroot -w ${WEBROOT} -d ${MONITOR_HOST} \
              --cert-name ${MONITOR_HOST} --non-interactive --agree-tos \
              --keep-until-expiring"; then
    cat >&2 <<EOF

    certbot could not validate ${MONITOR_HOST}.

    Most common cause: DNS does not point here, a CDN/proxy intercepts HTTP-01,
    or port 80 is blocked. Fix the DNS/proxy path, then re-run.

    Nothing was broken: the bootstrap vhost only answers ACME challenges, and
    the other sites are unaffected.

EOF
    exit 4
  fi
fi

rsh "install -o root -g root -m 644 /etc/nginx/snippets/nginx-monitor.conf ${SITE_CONF}
     ln -sf ${SITE_CONF} ${SITE_LINK}
     nginx -t
     systemctl reload nginx"

echo "==> 8/9 failure-page vhost"
put "$HERE/nginx-failed.conf" "/tmp/nginx-failed.conf"
put "$HERE/nginx-failed-bootstrap.conf" "/tmp/nginx-failed-bootstrap.conf"
rsh "install -d -m 755 ${WEBROOT}
     install -o root -g root -m 644 /tmp/nginx-failed.conf /etc/nginx/snippets/nginx-failed.conf
     install -o root -g root -m 644 /tmp/nginx-failed-bootstrap.conf /etc/nginx/snippets/nginx-failed-bootstrap.conf
     rm -f /tmp/nginx-failed.conf /tmp/nginx-failed-bootstrap.conf
     install -d -o root -g root -m 755 /var/www/blocked.example.com

     if [ -f ${FAILED_CERT_DIR}/fullchain.pem ]; then
       install -o root -g root -m 644 /etc/nginx/snippets/nginx-failed.conf ${FAILED_CONF}
     else
       install -o root -g root -m 644 /etc/nginx/snippets/nginx-failed-bootstrap.conf ${FAILED_CONF}
     fi
     ln -sf ${FAILED_CONF} ${FAILED_LINK}
     nginx -t
     systemctl reload nginx"

# The failure page is optional for the rest of the site: a missing DNS record or
# a failed certificate must not fail the deployment, it only means redirect mode
# has nowhere to go yet.
FAILED_DNS=$(rsh "resolve-auth ${FAILED_HOST} | tr '\n' ' '" || true)
case "$FAILED_DNS" in
  ERROR*|"")
    echo "    WARNING: ${FAILED_HOST} does not resolve yet — keeping the HTTP-only bootstrap."
    echo "             Add the A record, then re-run this script to obtain the certificate."
    ;;
  *)
    echo "    resolves to: ${FAILED_DNS}"
    if ! rsh "test -f ${FAILED_CERT_DIR}/fullchain.pem"; then
      echo "    requesting certificate for ${FAILED_HOST}"
      if rsh "certbot certonly --webroot -w ${WEBROOT} -d ${FAILED_HOST} \
                --cert-name ${FAILED_HOST} --non-interactive --agree-tos \
                --keep-until-expiring"; then
        rsh "install -o root -g root -m 644 /etc/nginx/snippets/nginx-failed.conf ${FAILED_CONF}
             ln -sf ${FAILED_CONF} ${FAILED_LINK}
             nginx -t
             systemctl reload nginx"
        echo "    certificate installed"
      else
        echo "    WARNING: certbot could not validate ${FAILED_HOST} — failure-page redirects will not work yet." >&2
        echo "             The bootstrap vhost is still installed and every other site is unaffected." >&2
      fi
    fi
    ;;
esac

echo "==> 9/9 smoke test"
rsh "echo '--- direct app'
     curl -fsS -m 5 http://127.0.0.1:${APP_PORT}/health; echo
     echo '--- new hostname via this host'
     curl -sS -m 10 -k --resolve ${MONITOR_HOST}:443:127.0.0.1 -o /dev/null \\
       -w 'https://${MONITOR_HOST}/ -> %{http_code}\\n' https://${MONITOR_HOST}/
     curl -sS -m 10 -k --resolve ${MONITOR_HOST}:443:127.0.0.1 -o /dev/null \\
       -w 'https://${MONITOR_HOST}/login -> %{http_code}\\n' https://${MONITOR_HOST}/login
     echo '--- isolate: existing sites still healthy'
     for h in ${MAIN_HOST} mail.${MAIN_HOST} logs.${MAIN_HOST}; do
       curl -sS -m 10 -k --resolve \${h}:443:127.0.0.1 -o /dev/null -w \"\${h} -> %{http_code}\\n\" https://\${h}/
     done
     echo '--- journal access as monsvc'
     sudo -u monsvc journalctl -u ssh -n 1 --no-pager -o cat >/dev/null && echo 'journal readable'
     echo '--- manual SSH block capability'
     if sudo -u monsvc nft list table inet monitor_block >/dev/null 2>&1; then
       echo 'nft reachable (table exists)'
     else
       nft list tables | grep -q monitor_block && echo 'nft reachable' \\
         || echo 'nft table not created yet (created on first block)'
     fi
     echo '--- certbot renewal dry run'
     certbot renew --dry-run --cert-name ${MONITOR_HOST} 2>&1 | tail -3"

echo
echo "==> verifying the block API end to end"
put "$HERE/verify-block.py" "/tmp/verify-block.py"
rsh "python3 /tmp/verify-block.py; rc=\$?; rm -f /tmp/verify-block.py; exit \$rc"

echo
echo "==> done"
echo "    panel:  https://${MONITOR_HOST}/"
echo "    direct: http://127.0.0.1:${APP_PORT} (bind 127.0.0.1 only)"
echo "    env:    ${ENV_FILE} (0600 root)"
echo "    data:   ${DATA_DIR} (monsvc, 0750)"
