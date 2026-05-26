# dev-infra

Per-host setup for running multiple sites in isolated, SSH-accessible Docker
containers, fronted by a shared Caddy reverse proxy with auto-TLS.

## Architecture

```
                  Internet
                      │
                      ▼
┌─────────────────────────────────────────────┐
│            Host (Hetzner box)               │
│                                             │
│  /srv/edge/  ── edge-caddy (auto-TLS)       │
│       │  watches Docker socket for labels   │
│       │                                     │
│       ▼                                     │
│  /srv/sites/<slug>/                         │
│       │  bind-mount → /home/dev             │
│       ▼                                     │
│  container `<slug>`                         │
│     - user `dev` (uid matches host user)    │
│     - vite dev server on :5173 (HMR)        │
│     - passwordless sudo, full toolchain     │
│                                             │
│  + host user `<slug>` with forced SSH       │
│    command → docker exec into container     │
└─────────────────────────────────────────────┘
```

One host can host many sites. Each site is one container = one shell jail.
Operators (or Claude Code via MCP) SSH in as `<slug>@<host>` and are dropped
straight into the container as the `dev` user.

## Installing on a fresh box

```bash
# Fresh Ubuntu 24.04 Hetzner box, as root:
git clone https://github.com/kingsoftheweb/dev-infra.git
cd dev-infra
sudo ./install.sh
```

That installs Docker, lays down `/srv/{edge,sites}`, brings up the edge Caddy,
and installs `bootstrap-site` into `/usr/local/bin/`.

## Onboarding a new site

```bash
sudo bootstrap-site \
  --slug futrx-com \
  --domain futrx-com.futrx.xyz \
  --repo git@github.com:kingsoftheweb/futrx.com.git \
  --branch development
```

The script:
1. Creates host user `futrx-com` with home `/srv/sites/futrx-com`
2. Generates an **operator SSH keypair** (you'll get the private half printed at the end)
3. Generates a **deploy keypair** and pauses for you to paste the pub half into GitHub repo settings (allow write access)
4. Clones the repo into `/srv/sites/futrx-com/<repo>/`
5. Builds + starts the container (it picks up `<repo>/Dockerfile` if present, else uses the template)
6. The edge Caddy auto-discovers the new container via labels and requests an LE cert

Public URL is live within ~30s of the script finishing.

## SSH-ing in

```bash
ssh -i <path-to-saved-operator-key> futrx-com@<host>
```

You land inside the container as user `dev`, cwd `/home/dev/app` (the bind-mounted repo). You can:

- Run `npm install <pkg>`, `git pull`, `git push`, `apt-get install …` (via sudo — alpine equivalent: `sudo apk add …`)
- Edit files with whatever editor you've installed
- Read logs: `tail -f /var/log/...`

You cannot escape the container. Filesystem changes outside `/home/dev` are local to the container layer and disappear if the image is rebuilt — persistence belongs in the repo or in the bind-mount.

## Project Dockerfile vs template

If your repo has a `Dockerfile`, the bootstrap script uses it as-is and skips copying the template. Otherwise it copies `site-template/Dockerfile` into the repo dir so the build has something to build from.

The template image gives you:
- Node 20 (alpine)
- bash, sudo, git, curl, wget, tini, openssh-client
- A `dev` user with passwordless sudo and a UID matching the host user

Override it in your repo's `Dockerfile` if you need more (e.g. python, playwright, ffmpeg).

## Files in this repo

| Path | Purpose |
|---|---|
| `install.sh` | One-shot installer for a fresh host |
| `edge/docker-compose.yml` | Global Caddy reverse proxy |
| `bootstrap-site.sh` | Onboard one site (run as root) |
| `site-template/Dockerfile` | Default container image |
| `site-template/docker-compose.yml` | Per-site compose |
| `site-template/start.sh` | In-container supervisor for `vite dev` |
| `site-template/.env.example` | Reference for what bootstrap writes to `.env` |

## Tearing down a site

```bash
sudo bash -c '
  SLUG=futrx-com
  cd /srv/sites/$SLUG && docker compose down -v
  userdel -r $SLUG 2>/dev/null || true
'
```

The edge Caddy notices the container is gone and stops routing the domain.
