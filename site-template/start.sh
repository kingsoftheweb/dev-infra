#!/usr/bin/env bash
# Foreground supervisor for the dev container.
# Keeps the dev server alive; restarts it if it crashes.

set -euo pipefail

REPO="${REPO_NAME:-app}"
HOME_DIR=/home/dev

# Ensure /home/dev/app is a symlink → the actual repo subdir.
# Docker may have created an empty root-owned dir there if WORKDIR/working_dir
# is set (we now omit both, but be defensive in case the image is older).
if [[ -L "$HOME_DIR/app" ]]; then
  : # already a symlink, fine
elif [[ -d "$HOME_DIR/app" ]]; then
  sudo rmdir "$HOME_DIR/app" 2>/dev/null || sudo rm -rf "$HOME_DIR/app"
fi
[[ -e "$HOME_DIR/app" ]] || ln -sfn "$HOME_DIR/$REPO" "$HOME_DIR/app"

cd "$HOME_DIR/app"

# Install deps if missing
if [[ ! -d node_modules ]]; then
  echo "[start.sh] installing deps via npm ci"
  npm ci --no-audit --no-fund
fi

# Loop so that `npm run dev` crashing doesn't kill the container
while true; do
  echo "[start.sh] launching: npm run dev"
  npm run dev -- --host 0.0.0.0 --port 5173 || {
    echo "[start.sh] dev server exited ($?); restarting in 3s"
    sleep 3
  }
done
