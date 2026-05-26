#!/usr/bin/env bash
# Bootstrap a fresh Hetzner Ubuntu host as a multi-site dev server.
#
# Run as root on a fresh Ubuntu 24.04 box:
#   curl -fsSL https://raw.githubusercontent.com/kingsoftheweb/dev-infra/main/install.sh | bash
# or after `git clone`-ing this repo:
#   sudo ./install.sh
#
# What it does:
#   1. Installs Docker (compose plugin included)
#   2. Lays down /srv/{edge,sites,login}/
#   3. Generates /srv/jwt-secret and an initial /srv/access.json if missing
#   4. Builds the dev-mcp and dev-login images
#   5. Brings up the edge stack (Caddy + login portal)
#   6. Installs `bootstrap-site` + the enter-site wrapper + the site template
#
# /srv/login/.env is your responsibility — it must contain:
#   GOOGLE_CLIENT_ID=<from Google Cloud Console OAuth client>
#   GOOGLE_CLIENT_SECRET=<from Google Cloud Console OAuth client>
#   COOKIE_SECRET=<random 32+ bytes>
# If missing, install.sh writes a template and exits so you can fill it in.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo $0)." >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Installing Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi

echo "==> Preparing /srv layout"
mkdir -p /srv/edge /srv/sites /srv/login
chmod 755 /srv /srv/sites
chmod 750 /srv/login

echo "==> Generating /srv/jwt-secret (if missing)"
if [[ ! -s /srv/jwt-secret ]]; then
  openssl rand -base64 64 | tr -d '\n' > /srv/jwt-secret
  chmod 640 /srv/jwt-secret
  echo "    new JWT-signing secret written."
else
  echo "    already present — leaving as-is."
fi

echo "==> Initializing /srv/access.json (if missing)"
if [[ ! -e /srv/access.json ]]; then
  cat > /srv/access.json <<'JSON'
{
  "users": {}
}
JSON
  chmod 644 /srv/access.json
  echo "    new (empty) access list created. Add users before they can sign in."
else
  echo "    already present — leaving as-is."
fi

echo "==> Checking /srv/login/.env"
if [[ ! -s /srv/login/.env ]]; then
  cat > /srv/login/.env <<EOF
# Google OAuth client (from console.cloud.google.com → APIs & Services → Credentials)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
# Random 32+ bytes for signing session cookies (this is separate from the JWT secret)
COOKIE_SECRET=$(openssl rand -base64 48 | tr -d '\n')
EOF
  chmod 600 /srv/login/.env
  echo
  echo "    Wrote a template at /srv/login/.env."
  echo "    Fill in GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, then re-run this script."
  exit 0
fi

if ! grep -qE '^GOOGLE_CLIENT_ID=.+' /srv/login/.env || \
   ! grep -qE '^GOOGLE_CLIENT_SECRET=.+' /srv/login/.env; then
  echo "    /srv/login/.env is missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET — fill them in, then re-run."
  exit 1
fi

echo "==> Building dev-mcp image (used by each site's mcp container)"
docker build -q -t dev-mcp:latest "$REPO_DIR/mcp-server/" >/dev/null

echo "==> Building dev-login image (the central login portal)"
docker build -q -t dev-login:latest "$REPO_DIR/login-portal/" >/dev/null

echo "==> Installing edge stack"
cp "$REPO_DIR/edge/docker-compose.yml" /srv/edge/docker-compose.yml

echo "==> Bringing up edge Caddy + login portal"
( cd /srv/edge && docker compose up -d )

echo "==> Installing bootstrap-site + enter-site + site template"
install -m 0755 "$REPO_DIR/bootstrap-site.sh" /usr/local/bin/bootstrap-site
install -d -m 0755 /usr/local/libexec
install -m 0755 "$REPO_DIR/libexec/enter-site.sh" /usr/local/libexec/enter-site
mkdir -p /usr/local/share/dev-infra
cp -r "$REPO_DIR/site-template" /usr/local/share/dev-infra/

echo
echo "==================================================================="
echo " Done."
echo
echo " Login portal:  https://login.apps.futrx.xyz (Caddy will issue LE cert"
echo "                on first request; can take ~30s)"
echo
echo " Add a user (edit /srv/access.json):"
echo '   {"users": {"you@example.com": {"sites": ["futrx-com"]}}}'
echo
echo " Onboard a new site:"
echo "   bootstrap-site \\"
echo "     --slug futrx-com \\"
echo "     --domain futrx-com.futrx.xyz \\"
echo "     --repo git@github.com:owner/repo.git \\"
echo "     --branch development"
echo "==================================================================="
