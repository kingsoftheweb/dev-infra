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
#   2. Lays down /srv/{edge,sites}/ and the edge Caddy stack
#   3. Brings up the edge Caddy (auto-TLS, auto-discovery via Docker labels)
#   4. Installs `bootstrap-site` into /usr/local/bin/
#   5. Installs the site template into /usr/local/share/dev-infra/

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
mkdir -p /srv/edge /srv/sites
chmod 755 /srv /srv/sites

echo "==> Installing edge stack"
cp "$REPO_DIR/edge/docker-compose.yml" /srv/edge/docker-compose.yml

echo "==> Bringing up edge Caddy"
( cd /srv/edge && docker compose up -d )

echo "==> Building dev-mcp image (used by each site's mcp container)"
docker build -t dev-mcp:latest "$REPO_DIR/mcp-server/"

echo "==> Installing bootstrap-site script + template + enter-site wrapper"
install -m 0755 "$REPO_DIR/bootstrap-site.sh" /usr/local/bin/bootstrap-site
install -d -m 0755 /usr/local/libexec
install -m 0755 "$REPO_DIR/libexec/enter-site.sh" /usr/local/libexec/enter-site
mkdir -p /usr/local/share/dev-infra
cp -r "$REPO_DIR/site-template" /usr/local/share/dev-infra/

echo
echo "==================================================================="
echo " Done. Edge Caddy is running on ports 80/443."
echo
echo " To onboard a new site:"
echo "   bootstrap-site --slug <name> --domain <host> --repo <git-ssh-url> [--branch <b>]"
echo
echo " Example:"
echo "   bootstrap-site \\"
echo "     --slug futrx-com \\"
echo "     --domain futrx-com.futrx.xyz \\"
echo "     --repo git@github.com:kingsoftheweb/futrx.com.git \\"
echo "     --branch development"
echo "==================================================================="
