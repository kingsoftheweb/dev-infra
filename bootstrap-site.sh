#!/usr/bin/env bash
# Onboard a new site on this host.
#
# Required:
#   --slug <name>                     short site name, used for host user, container, dir
#   --domain <host>                   public hostname (DNS A record must already exist)
#   --repo <git-ssh-url>              git@github.com:owner/repo.git
#
# Optional:
#   --branch <name>                   git branch (default: main)
#   --operator-pubkey <path>          path to an existing pub key — installed as authorized_keys.
#                                     If omitted, an operator keypair is generated on this host
#                                     and the private half is printed at the end (save it!).
#   --deploy-key <path>               path to an existing deploy keypair (expects <path> and <path>.pub).
#                                     If omitted, one is generated and you'll be paused to add the
#                                     pub half to the GitHub repo's Deploy Keys (allow write).
#   --non-interactive                 don't pause for deploy-key add. Implied by --deploy-key.
#
# Example (fully driven from elsewhere — keys generated outside, deploy pub already on GitHub):
#   bootstrap-site \
#     --slug futrx-com --domain futrx-com.futrx.xyz \
#     --repo git@github.com:kingsoftheweb/futrx.com.git --branch development \
#     --operator-pubkey /tmp/op.pub --deploy-key /tmp/deploy

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo $0 ...)." >&2
  exit 1
fi

# -------- args -----------------------------------------------------------
SLUG=""; DOMAIN=""; REPO=""; BRANCH="main"
OP_PUBKEY_IN=""; DEPLOY_KEY_IN=""; NON_INTERACTIVE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --slug)              SLUG="$2"; shift 2 ;;
    --domain)            DOMAIN="$2"; shift 2 ;;
    --repo)              REPO="$2"; shift 2 ;;
    --branch)            BRANCH="$2"; shift 2 ;;
    --operator-pubkey)   OP_PUBKEY_IN="$2"; shift 2 ;;
    --deploy-key)        DEPLOY_KEY_IN="$2"; NON_INTERACTIVE=1; shift 2 ;;
    --non-interactive)   NON_INTERACTIVE=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
if ! docker network inspect edge >/dev/null 2>&1; then
  echo "Edge network 'edge' not found. Run install.sh first." >&2
  exit 1
fi
if [[ ! -x /usr/local/libexec/enter-site ]]; then
  echo "/usr/local/libexec/enter-site missing. Run install.sh first." >&2
  exit 1
fi

# DNS preflight (best-effort)
EXPECTED_IP="$(curl -fsS https://ipv4.icanhazip.com || true)"
RESOLVED_IP="$(getent hosts "$DOMAIN" | awk '{print $1}' | head -1 || true)"
if [[ -n "$EXPECTED_IP" && "$RESOLVED_IP" != "$EXPECTED_IP" ]]; then
  echo "WARN: $DOMAIN resolves to '${RESOLVED_IP:-<unresolved>}' but this host is $EXPECTED_IP."
  echo "      Caddy will keep retrying ACME until DNS is correct."
  if [[ "$NON_INTERACTIVE" != "1" ]]; then
    read -rp "Continue? [y/N] " a; [[ "$a" =~ ^[Yy]$ ]] || exit 1
  fi
fi

REPO_NAME="$(basename "$REPO" .git)"

# -------- host user ------------------------------------------------------
NEXT_UID="$(awk -F: '$3>=1500 && $3<60000 {print $3}' /etc/passwd | sort -n | tail -1)"
NEXT_UID="$(( ${NEXT_UID:-1499} + 1 ))"

echo "==> Creating host user '$SLUG' (uid $NEXT_UID), home $SITE_DIR, shell /bin/bash"
useradd --create-home --home-dir "$SITE_DIR" --uid "$NEXT_UID" \
        --shell /bin/bash "$SLUG"

# The user needs docker-socket access so the forced-command wrapper can run
# `docker exec`. The only thing they can do as the docker group is exactly
# what their authorized_keys forced command lets them — they can't get an
# interactive host shell (no PTY, no command override). Container is the jail.
usermod -aG docker "$SLUG"

# -------- ssh keys -------------------------------------------------------
install -d -o "$SLUG" -g "$SLUG" -m 700 "$SITE_DIR/.ssh"

OP_PUB_DEST="$SITE_DIR/.ssh/authorized_keys"
DEPLOY_KEY="$SITE_DIR/.ssh/deploy_ed25519"

# Operator pub key: either install supplied, or generate a keypair here.
GENERATED_OP_PRIV=""
if [[ -n "$OP_PUBKEY_IN" ]]; then
  [[ -f "$OP_PUBKEY_IN" ]] || { echo "operator pubkey not found: $OP_PUBKEY_IN" >&2; exit 1; }
  PUB_KEY_CONTENT="$(cat "$OP_PUBKEY_IN")"
else
  OP_KEY="$SITE_DIR/.ssh/operator_ed25519"
  sudo -u "$SLUG" ssh-keygen -t ed25519 -N "" -C "$SLUG-operator" -f "$OP_KEY" >/dev/null
  PUB_KEY_CONTENT="$(cat "$OP_KEY.pub")"
  GENERATED_OP_PRIV="$OP_KEY"
fi

# Forced-command authorized_keys entry. The wrapper handles interactive
# vs non-interactive automatically.
cat > "$OP_PUB_DEST" <<EOF
command="/usr/local/libexec/enter-site $SLUG",no-port-forwarding,no-X11-forwarding,no-agent-forwarding $PUB_KEY_CONTENT
EOF
chown "$SLUG":"$SLUG" "$OP_PUB_DEST"
chmod 600 "$OP_PUB_DEST"

# Deploy key: either install supplied, or generate.
if [[ -n "$DEPLOY_KEY_IN" ]]; then
  [[ -f "$DEPLOY_KEY_IN" && -f "$DEPLOY_KEY_IN.pub" ]] || {
    echo "deploy keypair not found: $DEPLOY_KEY_IN (and $DEPLOY_KEY_IN.pub)" >&2; exit 1; }
  install -o "$SLUG" -g "$SLUG" -m 600 "$DEPLOY_KEY_IN"     "$DEPLOY_KEY"
  install -o "$SLUG" -g "$SLUG" -m 644 "$DEPLOY_KEY_IN.pub" "$DEPLOY_KEY.pub"
else
  sudo -u "$SLUG" ssh-keygen -t ed25519 -N "" -C "$SLUG-deploy" -f "$DEPLOY_KEY" >/dev/null
  echo
  echo "============================================================"
  echo " Add this DEPLOY public key to the GitHub repo (allow write):"
  echo
  cat "$DEPLOY_KEY.pub"
  echo
  echo "    Repo settings → Deploy keys → Add deploy key"
  echo "    [x] Allow write access"
  echo "============================================================"
  if [[ "$NON_INTERACTIVE" != "1" ]]; then
    read -rp "Press Enter once added... " _
  fi
fi

# Persistent ssh config: future git ops from inside the container use the deploy key
sudo -u "$SLUG" tee "$SITE_DIR/.ssh/config" >/dev/null <<EOF
Host github.com
  HostName github.com
  User git
  IdentityFile /home/dev/.ssh/deploy_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
EOF
chmod 600 "$SITE_DIR/.ssh/config"

# -------- clone repo -----------------------------------------------------
REPO_DIR="$SITE_DIR/$REPO_NAME"
echo "==> Cloning $REPO ($BRANCH) into $REPO_DIR"
sudo -u "$SLUG" -H \
  env GIT_SSH_COMMAND="ssh -i $DEPLOY_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new" \
  git clone --branch "$BRANCH" --single-branch "$REPO" "$REPO_DIR"

# -------- write per-site compose ----------------------------------------
TEMPLATE=/usr/local/share/dev-infra/site-template
install -m 0644 "$TEMPLATE/docker-compose.yml" "$SITE_DIR/docker-compose.yml"
install -m 0755 "$TEMPLATE/start.sh"           "$SITE_DIR/start.sh"

# Use the repo's own Dockerfile if it has one, else fall back to the template.
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

# -------- bring up container --------------------------------------------
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

if [[ -n "$GENERATED_OP_PRIV" ]]; then
  echo
  echo " ─── OPERATOR PRIVATE KEY (save this, you'll need it to SSH in) ───"
  cat "$GENERATED_OP_PRIV"
  echo " ───────────────────────────────────────────────────────────────────"
fi
echo "============================================================"
