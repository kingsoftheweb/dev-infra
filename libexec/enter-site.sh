#!/usr/bin/env bash
# Forced-command wrapper for SSH access to a per-site container.
#
# Installed by install.sh into /usr/local/libexec/enter-site.
# Referenced from each site's ~/.ssh/authorized_keys via:
#   command="/usr/local/libexec/enter-site <slug>" ssh-ed25519 AAAA...
#
# Behavior:
#   - If the SSH client requested an interactive session (no command), we
#     drop them into a login bash inside the container (`docker exec -it`).
#   - If the SSH client passed a command (scripts, MCP, etc.), we run it
#     non-interactively (`docker exec -i`) and exit with its status.
#
# Either way, the host is unreachable — everything happens inside the
# container as user `dev`.

set -euo pipefail

SLUG="${1:?slug required}"

if [[ -z "${SSH_ORIGINAL_COMMAND:-}" ]]; then
  exec docker exec -it -u dev -w /home/dev/app "$SLUG" /bin/bash -l
else
  exec docker exec -i -u dev -w /home/dev/app "$SLUG" /bin/bash -c "$SSH_ORIGINAL_COMMAND"
fi
