#!/usr/bin/env bash
# Onboard a new site on this host.
#
# Creates:
#   - A non-login host user <slug> with home /srv/sites/<slug> (uid auto-assigned ≥1500)
#   - An SSH keypair for that user; pub goes into ~<slug>/.ssh/authorized_keys
#     with a forced command that drops the connection straight into the container
#   - A deploy keypair (you paste the pub half into GitHub repo settings)
#   - A git clone of the repo at /srv/sites/<slug>/<repo-name>/
#   - A Docker container running Node + Vite (HMR) + bind-mount of the source,
#     labeled so the edge Caddy auto-routes the domain to it
#
# Outputs the private SSH key to stdout. Save it — that's how the operator
# (or Claude Code MCP) SSHes into the container.
#
# Usage:
#   bootstrap-site --slug <name> --domain <host> --repo <git-ssh-url> [--branch <b>]
#
# Example:
#   bootstrap-site \
#     --slug futrx-com \
#     --domain futrx-com.futrx.xyz \
#     --repo git@github.com:kingsoftheweb/futrx.com.git \
#     --branch development

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo $0 ...)." >&2
  exit 1
fi

# -------- args -----------------------------------------------------------
SLUG=""; DOMAIN=""; REPO=""; BRANCH="main"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --slug)    SLUG="$2";    shift 2 ;;
    --domain)  DOMAIN="$2";  shift 2 ;;
    --repo)    REPO="$2";    shift 2 ;;
    --branch)  BRANCH="$2";  shift 2 ;;
    -h|--help) sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done
: "${SLUG:?--slug required}"
: "${DOMAIN:?--domain required}"
: "${REPO:?--repo required (git SSH URL)}"

# -------- preflight ------------------------------------------------------
SITE_DIR="/srv/sites/$SLUG"
if [[ -e "$SITE_DIR" ]]; then
  echo "$SITE_DIR already exists. Pick a different slug or remove it first." >&2
  exit 1
fi
if id "$SLUG" >/dev/null 2>&1; then
  echo "User '$SLUG' already exists. Pick a different slug." >&2
  exit 1
fi

# Verify the edge stack is running (so labels actually take effect)
if ! docker network inspect edge >/dev/null 2>&1; then
  echo "Edge network 'edge' not found. Run install.sh first." >&2
  exit 1
fi

# DNS preflight (best-effort warning, doesn't block)
EXPECTED_IP="$(curl -fsS https://ipv4.icanhazip.com || true)"
RESOLVED_IP="$(getent hosts "$DOMAIN" | awk '{print $1}' | head -1 || true)"
if [[ -n "$EXPECTED_IP" && "$RESOLVED_IP" != "$EXPECTED_IP" ]]; then
  echo "WARN: $DOMAIN resolves to '${RESOLVED_IP:-<unresolved>}' but this host is $EXPECTED_IP."
  echo "      Caddy will keep retrying ACME until DNS is correct. Continue? [y/N]"
  read -r answer
  [[ "$answer" =~ ^[Yy]$ ]] || exit 1
fi

REPO_NAME="$(basename "$REPO" .git)"

# -------- host user ------------------------------------------------------
# Allocate UID ≥ 1500 (one above the last existing one)
NEXT_UID="$(awk -F: '$3>=1500 && $3<60000 {print $3}' /etc/passwd | sort -n | tail -1)"
NEXT_UID="$(( ${NEXT_UID:-1499} + 1 ))"

echo "==> Creating host user '$SLUG' (uid $NEXT_UID), home $SITE_DIR"
useradd --create-home --home-dir "$SITE_DIR" --uid "$NEXT_UID" \
        --shell /usr/sbin/nologin "$SLUG"

# -------- ssh keys -------------------------------------------------------
install -d -o "$SLUG" -g "$SLUG" -m 700 "$SITE_DIR/.ssh"

OP_KEY="$SITE_DIR/.ssh/operator_ed25519"
DEPLOY_KEY="$SITE_DIR/.ssh/deploy_ed25519"
sudo -u "$SLUG" ssh-keygen -t ed25519 -N "" -C "$SLUG-operator" -f "$OP_KEY" >/dev/null
sudo -u "$SLUG" ssh-keygen -t ed25519 -N "" -C "$SLUG-deploy"   -f "$DEPLOY_KEY" >/dev/null

# Forced-command authorized_keys: ssh-ing in lands directly inside the container
AUTH_KEYS="$SITE_DIR/.ssh/authorized_keys"
PUB_KEY_CONTENT="$(cat "$OP_KEY.pub")"
cat > "$AUTH_KEYS" <<EOF
command="docker exec -i -u dev -w /home/dev/app $SLUG /bin/bash -l",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty $PUB_KEY_CONTENT
EOF
# We DO want a pty for interactive — drop the no-pty restriction for interactive
sed -i 's/,no-pty //' "$AUTH_KEYS"
chown "$SLUG":"$SLUG" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

# -------- deploy key + clone --------------------------------------------
echo
echo "============================================================"
echo " Add this DEPLOY public key to the GitHub repo (allow write):"
echo
cat "$DEPLOY_KEY.pub"
echo
echo "    Repo settings → Deploy keys → Add deploy key"
echo "    [x] Allow write access"
echo "============================================================"
read -rp "Press Enter once added... " _

REPO_DIR="$SITE_DIR/$REPO_NAME"
echo "==> Cloning $REPO ($BRANCH) into $REPO_DIR"
sudo -u "$SLUG" -H \
  env GIT_SSH_COMMAND="ssh -i $DEPLOY_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new" \
  git clone --branch "$BRANCH" --single-branch "$REPO" "$REPO_DIR"

# Persistent ssh config so future `git pull`/`git push` from inside the container use the deploy key
sudo -u "$SLUG" tee "$SITE_DIR/.ssh/config" >/dev/null <<EOF
Host github.com
  HostName github.com
  User git
  IdentityFile /home/dev/.ssh/deploy_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
EOF
chmod 600 "$SITE_DIR/.ssh/config"

# -------- write per-site compose -----------------------------------------
TEMPLATE=/usr/local/share/dev-infra/site-template
install -m 0644 "$TEMPLATE/docker-compose.yml" "$SITE_DIR/docker-compose.yml"
install -m 0755 "$TEMPLATE/start.sh"           "$SITE_DIR/start.sh"

# Per-site Dockerfile: use the repo's own if it has one, else fall back to template
if [[ ! -f "$REPO_DIR/Dockerfile" ]]; then
  install -m 0644 "$TEMPLATE/Dockerfile" "$REPO_DIR/Dockerfile"
fi

cat > "$SITE_DIR/.env" <<EOF
SLUG=$SLUG
DOMAIN=$DOMAIN
REPO_NAME=$REPO_NAME
DEV_UID=$NEXT_UID
EOF
chown "$SLUG":"$SLUG" "$SITE_DIR/.env" "$SITE_DIR/docker-compose.yml" "$SITE_DIR/start.sh"

# -------- bring up container ---------------------------------------------
echo "==> Building and starting container ($SLUG)"
( cd "$SITE_DIR" && docker compose up -d --build )

# -------- summary --------------------------------------------------------
echo
echo "============================================================"
echo " Site '$SLUG' is up."
echo
echo " Public URL:    https://$DOMAIN  (LE cert ~30s after first start)"
echo " SSH command:   ssh $SLUG@$(hostname -f 2>/dev/null || hostname)"
echo " Container:     docker logs -f $SLUG"
echo
echo " ─── OPERATOR PRIVATE KEY (save this, you'll need it to SSH in) ───"
cat "$OP_KEY"
echo " ───────────────────────────────────────────────────────────────────"
echo
echo " The deploy key lives at $DEPLOY_KEY (already on GitHub)."
echo "============================================================"
