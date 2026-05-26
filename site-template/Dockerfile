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
#
# Base image:
#   We use node:20-slim (Debian) rather than alpine. Many modern JS deps
#   ship glibc-only binaries (workerd for Cloudflare Workers, sharp,
#   playwright, prisma, esbuild's optional native binaries) and fail with
#   a cryptic "not found" on musl. Slim is ~50 MB compressed vs alpine ~40,
#   trivial trade for working out of the box on every framework.

FROM node:20-slim

ARG DEV_UID=1500

# bash + sudo + git + curl + tini: minimum DX. ca-certificates so the
# Node-side TLS calls work. tini gives clean PID 1 / signal handling so
# `docker stop` actually shuts vite down promptly.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash sudo git curl wget tini ca-certificates openssh-client procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid "$DEV_UID" --shell /bin/bash dev \
 && echo "dev ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/dev \
 && chmod 0440 /etc/sudoers.d/dev

USER dev
# No WORKDIR set: Docker would create /home/dev/app as a root-owned dir
# *over* the bind-mount, breaking start.sh's symlink. start.sh `cd`s into
# the right place itself.

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/home/dev/start.sh"]
