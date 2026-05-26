# Per-site dev container — Node + git + sudo + the dev `dev` user.
#
# The bootstrap-site script copies this file into a site's repo if the repo
# doesn't have its own Dockerfile. Apps can ship their own version to add
# project-specific tools (playwright, python, etc.).
#
# Conventions this image relies on:
#   - The build arg DEV_UID matches the host user's UID for the site, so
#     bind-mounted files have aligned ownership inside and outside.
#   - /home/dev/app is bind-mounted to the repo's working tree.
#   - The container's CMD runs start.sh (provided by the site dir), which
#     keeps the dev server alive in the foreground.

FROM node:20-alpine

ARG DEV_UID=1500

# bash, sudo, git: minimum DX. curl/wget: convenience for `docker exec` and
# for sudo-installing more later. tini: clean PID 1 / signal handling so
# `docker stop` actually shuts vite down promptly.
RUN apk add --no-cache bash sudo git curl wget tini openssh-client \
 && adduser -D -u "$DEV_UID" -s /bin/bash dev \
 && echo "dev ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/dev \
 && chmod 0440 /etc/sudoers.d/dev

USER dev
WORKDIR /home/dev/app

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/home/dev/start.sh"]
