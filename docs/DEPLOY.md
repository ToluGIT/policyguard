# Deploying the PolicyGuard GUI

The web GUI (`policyguard serve`) can be hosted publicly. It is designed for this:
in `--public` mode it accepts **upload/paste only** (no filesystem path scanning),
confines module sources to the upload, enforces tight size/file/rate/timeout
limits, loads only the trusted embedded policies, and escapes all rendered
content. See [SECURITY.md → Hosting the GUI](SECURITY.md#hosting-the-gui).

## Local container

```bash
docker build -f Dockerfile.gui -t policyguard-gui .
docker run --rm -p 8080:8080 policyguard-gui
# open http://localhost:8080
```

## Fly.io

The repo ships [`fly.toml`](../fly.toml) + [`Dockerfile.gui`](../Dockerfile.gui).

```bash
# 1. Install flyctl and sign in
brew install flyctl          # or: curl -L https://fly.io/install.sh | sh
fly auth login

# 2. Create the app (the committed fly.toml already has the settings, so skip the wizard's)
fly launch --no-deploy --copy-config --name policyguard

# 3. Ship it
fly deploy
```

`fly deploy` builds `Dockerfile.gui`, which runs `policyguard serve --public
--addr 0.0.0.0:8080` as a non-root user. `force_https = true` makes Fly terminate
TLS in front of the container, and `auto_stop_machines`/`min_machines_running = 0`
scale it to zero when idle (cheap for a demo).

### Custom domain — policyguard.tolubanji.com

```bash
# 1. Tell Fly to issue a certificate for the hostname
fly certs add policyguard.tolubanji.com

# 2. fly certs show prints the exact records; add them at your DNS provider:
#    - CNAME  policyguard  ->  policyguard.fly.dev
#    (or the A/AAAA records Fly prints, if you prefer apex-style)
fly certs show policyguard.tolubanji.com

# 3. Once DNS propagates, Fly auto-provisions the Let's Encrypt cert.
fly certs check policyguard.tolubanji.com
```

After the cert goes green, `https://policyguard.tolubanji.com` serves the GUI.

## Notes

- **Why public mode is safe to host:** the [GUI threat model](SECURITY.md#hosting-the-gui)
  covers module-source confinement, upload limits, generic error messages (no
  server path leakage), rate limiting, and CSP. Uploaded content is written to a
  temp dir and deleted after each scan.
- **Resource sizing:** scans are capped (1 MiB / 25 files / 15 s in public mode),
  so a single shared-CPU / 512 MB machine handles the demo workload.
- **Other platforms:** any container host works — the image is a single static
  binary. Render, Cloud Run, or a plain VM behind a TLS proxy are all fine; just
  run `policyguard serve --public --addr 0.0.0.0:<port>`.
