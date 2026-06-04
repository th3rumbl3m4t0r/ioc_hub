#!/usr/bin/env bash
#
# IoCHub installer — FRESH INSTALL on RHEL 9.8.
# Run as root:   sudo ./deploy.sh
#
# This script is for a NEW installation only. It does not upgrade or migrate an
# existing IoCHub: if it finds one already installed at the target prefix it
# stops and asks you to remove it first, so it can never clobber existing
# accounts/graphs by surprise.
#
# TLS: this build expects a real certificate to already exist on the host
# (e.g. issued by certbot/Let's Encrypt). It does NOT generate a self-signed
# certificate. The Apache vhost points at the certbot layout:
#   /etc/letsencrypt/live/<ServerName>/{fullchain,privkey}.pem
#
# Required/optional env vars:
#   IOCHUB_SERVER_NAME   (required) ServerName for the vhost + the cert dir name,
#                        e.g. iochub.example.org
#   IOCHUB_CERT_DIR      directory holding fullchain.pem + privkey.pem
#                        (default: /etc/letsencrypt/live/<IOCHUB_SERVER_NAME>)
#   IOCHUB_PREFIX        install root (default: /opt/iochub)
#   IOCHUB_ADMIN_PASSWORD  seed password for the admin account on first start
#                        (default: "IoChUb" — CHANGE IT after first login)
#
# What it does (fresh install):
#   * verifies no existing IoCHub is installed at the prefix
#   * installs httpd, mod_ssl, curl, bind-utils, whois, nmap (via dnf)
#   * creates the unprivileged `iochub` service account
#   * installs the backend binary + frontend under /opt/iochub
#   * installs and starts the systemd service (backend on 127.0.0.1:8787)
#   * installs Apache vhosts: iochub.conf (80->443 redirect) and
#     iochub-le-ssl.conf (443 reverse-proxy) using your existing TLS cert
#   * opens firewalld http/https and sets the SELinux proxy boolean

set -euo pipefail

PREFIX="${IOCHUB_PREFIX:-/opt/iochub}"
SVC_USER="iochub"
BACKEND_PORT="8787"
SERVER_NAME="${IOCHUB_SERVER_NAME:-}"
CERT_DIR="${IOCHUB_CERT_DIR:-/etc/letsencrypt/live/${SERVER_NAME}}"

say()  { printf '\n\033[1;33m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32mok\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo ./deploy.sh)"

# --- RHEL 9.8 sanity check -------------------------------------------------
# This build targets RHEL 9.8 (glibc 2.34). It will not run on RHEL < 9.0.
if [ -r /etc/redhat-release ]; then
    REL="$(cat /etc/redhat-release)"
    case "$REL" in
        *"release 9"*) ok "detected: $REL" ;;
        *) say "WARNING: this installer targets RHEL 9.8; detected: $REL" ;;
    esac
else
    say "WARNING: /etc/redhat-release not found; this installer targets RHEL 9.8."
fi

[ -n "$SERVER_NAME" ] || die "set IOCHUB_SERVER_NAME first, e.g.:
    sudo IOCHUB_SERVER_NAME=iochub.example.org ./deploy.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="$SCRIPT_DIR/payload"
[ -d "$PAYLOAD" ] || die "payload/ directory not found next to deploy.sh"
[ -f "$PAYLOAD/iochub" ] || die "payload/iochub binary missing"
[ -f "$PAYLOAD/index.html" ] || [ -d "$PAYLOAD/public" ] || die "frontend payload missing"
[ -f "$SCRIPT_DIR/iochub.conf" ] || die "iochub.conf vhost template missing next to deploy.sh"
[ -f "$SCRIPT_DIR/iochub-le-ssl.conf" ] || die "iochub-le-ssl.conf vhost template missing next to deploy.sh"

# --- refuse to run over an existing installation ---------------------------
# Fresh-install only: do not touch an existing IoCHub. The operator must remove
# it deliberately (this protects existing accounts/graphs).
EXISTING=0
[ -e "$PREFIX/iochub" ] && EXISTING=1
[ -d "$PREFIX/data" ] && EXISTING=1
systemctl cat iochub >/dev/null 2>&1 && EXISTING=1
[ -f /etc/systemd/system/iochub.service ] && EXISTING=1
if [ "$EXISTING" = "1" ]; then
    die "an existing IoCHub installation was detected (at $PREFIX or as a systemd
    unit). This installer only performs a FRESH install and will not modify or
    upgrade it. To reinstall from scratch, first stop and remove the old one:
        systemctl disable --now iochub
        rm -f /etc/systemd/system/iochub.service && systemctl daemon-reload
        rm -rf $PREFIX
        rm -f /etc/httpd/conf.d/iochub.conf /etc/httpd/conf.d/iochub-le-ssl.conf
    (back up $PREFIX/data first if you want to keep accounts/graphs), then re-run."
fi

if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ]; then
    say "WARNING: TLS cert not found at $CERT_DIR (fullchain.pem / privkey.pem)."
    echo "    Apache will fail to start until the cert exists. If your cert lives"
    echo "    elsewhere, re-run with  IOCHUB_CERT_DIR=/path/to/certdir  set, or"
    echo "    obtain one first, e.g.:  certbot --apache -d ${SERVER_NAME}"
fi

say "Installing IoCHub  (ServerName: $SERVER_NAME, prefix: $PREFIX)"

# --- 1. packages -----------------------------------------------------------
say "Installing packages (httpd, mod_ssl, curl, bind-utils, whois, nmap)"
dnf -y install httpd mod_ssl >/dev/null
command -v curl >/dev/null 2>&1 || dnf -y install curl >/dev/null
# Tools for the host-analysis features (domain dig/whois, IP nmap). bind-utils
# provides `dig`. Best-effort: a missing tool just disables its part.
dnf -y install bind-utils whois nmap >/dev/null 2>&1 || \
  ok "note: could not install bind-utils/whois/nmap — host analysis will be partial until installed"
ok "packages present"

# --- 2. service account ----------------------------------------------------
say "Service account: $SVC_USER"
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$PREFIX" --shell /sbin/nologin "$SVC_USER"
    ok "created user $SVC_USER"
else
    ok "user $SVC_USER already exists"
fi

# --- 3. files --------------------------------------------------------------
say "Installing files under $PREFIX"
install -d -m 0755 "$PREFIX" "$PREFIX/public"
install -d -m 0750 "$PREFIX/data" "$PREFIX/data/graphs"
install -m 0755 "$PAYLOAD/iochub" "$PREFIX/iochub"

# Frontend may be shipped flat or under public/.
if [ -d "$PAYLOAD/public" ]; then
    cp -a "$PAYLOAD/public/." "$PREFIX/public/"
else
    cp -a "$PAYLOAD/index.html" "$PAYLOAD/app.css" "$PAYLOAD/app.js" "$PREFIX/public/"
    [ -d "$PAYLOAD/vendor" ] && cp -a "$PAYLOAD/vendor" "$PREFIX/public/"
fi

chown -R "$SVC_USER:$SVC_USER" "$PREFIX"
chmod 0750 "$PREFIX/data"
[ -f "$PAYLOAD/README.md" ] && install -m 0644 "$PAYLOAD/README.md" "$PREFIX/README.md"
ok "binary + frontend installed"

# --- 4. systemd ------------------------------------------------------------
say "Installing systemd service"
install -m 0644 "$PAYLOAD/iochub.service" /etc/systemd/system/iochub.service
systemctl daemon-reload
systemctl enable --now iochub >/dev/null
sleep 1
if curl -fsS "http://127.0.0.1:${BACKEND_PORT}/healthz" >/dev/null 2>&1; then
    ok "backend healthy on 127.0.0.1:${BACKEND_PORT}"
else
    systemctl --no-pager --full status iochub || true
    die "backend did not come up; see 'journalctl -u iochub'"
fi

# --- 5. TLS certificate (must already exist) -------------------------------
say "TLS certificate"
if [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]; then
    ok "using existing certificate in $CERT_DIR"
else
    say "WARNING: $CERT_DIR/fullchain.pem or privkey.pem not found."
    echo "    The vhost will reference them anyway; obtain/point to a real cert"
    echo "    (e.g. certbot --apache -d ${SERVER_NAME}) before httpd will serve TLS."
fi

# --- 6. Apache vhosts ------------------------------------------------------
say "Installing Apache vhosts (iochub.conf + iochub-le-ssl.conf)"
CERT_DIR_ESC="${CERT_DIR//\//\\/}"
sed "s/IOCHUB_SERVER_NAME/${SERVER_NAME}/g" "$SCRIPT_DIR/iochub.conf" \
    > /etc/httpd/conf.d/iochub.conf
sed -e "s/IOCHUB_SERVER_NAME/${SERVER_NAME}/g" \
    -e "s/IOCHUB_CERT_DIR/${CERT_DIR_ESC}/g" "$SCRIPT_DIR/iochub-le-ssl.conf" \
    > /etc/httpd/conf.d/iochub-le-ssl.conf
ok "vhosts written to /etc/httpd/conf.d/{iochub.conf,iochub-le-ssl.conf}"

# --- 7. SELinux ------------------------------------------------------------
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
    say "SELinux: allowing httpd outbound proxy"
    setsebool -P httpd_can_network_connect 1
    ok "httpd_can_network_connect = on"
fi

# --- 8. firewall -----------------------------------------------------------
if systemctl is-active --quiet firewalld; then
    say "Opening firewall (http, https)"
    firewall-cmd --permanent --add-service=http  >/dev/null
    firewall-cmd --permanent --add-service=https >/dev/null
    firewall-cmd --reload >/dev/null
    ok "ports 80/443 open"
fi

# --- 9. start Apache -------------------------------------------------------
say "Starting Apache"
apachectl configtest
systemctl enable --now httpd >/dev/null
systemctl reload httpd 2>/dev/null || systemctl restart httpd
ok "httpd running"

say "Done."
cat <<EOF

  IoCHub is live:   https://${SERVER_NAME}/

  Next steps:
    1. Open the URL. TLS uses your existing certificate:
         ${CERT_DIR}/fullchain.pem
         ${CERT_DIR}/privkey.pem
       If you renew or move it, update /etc/httpd/conf.d/iochub-le-ssl.conf
       and run:  systemctl reload httpd
    2. Log in as the seeded admin (username 'vmarik'). The default seed password
       is "IoChUb" unless you set IOCHUB_ADMIN_PASSWORD before first start.
       CHANGE IT IMMEDIATELY via the change-password panel. Then use the session
       panel to create additional users. Open registration is disabled.
    3. Settings -> save your VirusTotal API key (encrypted in your browser with
       your password; the server stores only ciphertext and relays VT calls).
    4. (Optional) MISP: set your MISP instance URL + API key in Settings. MISP
       queries go directly from your browser, so add your MISP origin to the
       connect-src in /etc/httpd/conf.d/iochub-le-ssl.conf, then reload httpd.
    5. (Optional) CAPE sandbox: edit ${PREFIX}/data/cape.conf and set 'url'
       (and 'token') to point at a CAPE instance you run yourself. IoCHub drives
       it over REST; it does not install or manage CAPE. Restrict [allow] when
       ready (default .* = everyone).

  Useful:
    systemctl status iochub        # backend
    journalctl -u iochub -f        # backend logs
    systemctl status httpd         # web front end
    httpd -t                       # validate Apache config / vhosts
EOF
