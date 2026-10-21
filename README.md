# emsign-trust-check

A self-hostable, intranet-friendly checker for the **October 2026 eMudhra intermediate CA compromise** ("emSign certificate vulnerability"). It detects whether browsers on your network still trust the eight compromised eMudhra intermediate CAs (16 certificates including the Sectigo cross-signs).

Inspired by and data-sourced from [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/).

## Why self-host?

The compromised intermediates were blocked by Firefox/Chrome (Oct 17), Apple (Oct 19) and Microsoft (Oct 20) via revocation push mechanisms (CRLite, CRLSets, Disallowed CTL). **Long-offline intranet machines may never receive those pushes.** This tool is meant to be deployed inside your LAN so every machine can be checked from a central URL.

## What's inside

| Path | Description |
|---|---|
| `public/index.html` | English live-check page — probes 12 test hosts signed by the compromised intermediates. **Connected = still trusted = at risk.** |
| `public/zh.html` | 中文版检测页面（内容相同） |
| `public/downloads/Check-EmSignTrust.ps1` | Offline Windows checker: Disallowed CTL fingerprint comparison + browser inventory + optional live TLS probes. Works on machines with no Internet at all. |
| `public/downloads/fingerprints.json` | SHA-1/SHA-256 fingerprints of all 16 compromised certs (computed from PEM, SHA-256 verified against the official list). |
| `public/downloads/impacted-intermediates.json` | Official certificate data (with PEM) for offline chain verification with OpenSSL. |

## Run with Docker

```bash
docker build -t emsign-trust-check .
docker run -d --name emsign-trust-check -p 8080:80 --restart unless-stopped emsign-trust-check
```

or with Compose:

```bash
docker compose up -d
```

Then have every intranet machine open `http://<server>:8080/` in **each installed browser** and click **Run check**:

- ❌ **Connected** — the browser still trusts the compromised chain → at risk
- ✅ **Did not connect** — blocked by certificate validation → protected
- ⚠️ **Timed out** — inconclusive; if *all* rows time out, the machine has no external access → use the offline script instead

> The live check probes the public test domains run by the original disclosure site, so the *checking machine* (not the Docker host) needs to reach `*.we-have-a-problem.com`. For air-gapped machines, use `downloads/Check-EmSignTrust.ps1`.

## Deploying on an air-gapped network (no Internet at all)

The container is 100% static: it needs no registry, no CDN, no external asset at runtime. Everything is baked into the image, so an offline host only needs the exported tarball.

On a machine **with** Docker and Internet (the build host):

```bash
./scripts/build-offline-bundle.sh 1.0.0
```

This produces:

| Artifact | Use |
|---|---|
| `dist/emsign-trust-check-1.0.0-docker-amd64.tar.gz` | `docker load` on offline hosts — the entire image, no registry pull |
| `dist/emsign-trust-check-1.0.0-static.tar.gz` | plain web root + scripts for hosts **without** Docker |
| `dist/SHA256SUMS` | integrity check before rollout |

On the offline host (copy `dist/` via USB or an internal share):

```bash
sha256sum -c SHA256SUMS

# Docker present:
tar xzf emsign-trust-check-1.0.0-static.tar.gz && cd emsign-trust-check-1.0.0
sudo ./scripts/install-offline.sh --docker --image ../dist/emsign-trust-check-1.0.0-docker-amd64.tar.gz

# No Docker (needs only python3, served via systemd):
sudo ./scripts/install-offline.sh --port 8080
```

Both modes verify themselves on `http://127.0.0.1:<port>/` using loopback only — no Internet required. To prove the container has no external dependency, you can run it with networking fully disabled:

```bash
docker run --rm --network none emsign-trust-check:1.0.0 sh -c 'wget -qO- http://127.0.0.1/ | head -3'
```

> Note: the *live check page* still probes the public test domains, so it is inconclusive on isolated hosts — that is expected. Use the offline scripts there; the page itself loads and works fine without Internet.

## Offline checking (Windows, no Internet)

```powershell
powershell -ExecutionPolicy Bypass -File Check-EmSignTrust.ps1 -SkipOnline
```

Three layers: Windows Disallowed CTL fingerprint match → browser version inventory → optional live TLS probes via `curl.exe` (Schannel). Verdicts: `PROTECTED` / `LIKELY-VULNERABLE` / `VULNERABLE`.

Batch collection across a domain (one CSV row per machine):

```powershell
powershell -ExecutionPolicy Bypass -File \\fileserver\share\Check-EmSignTrust.ps1 -SkipOnline -ExportCsv \\fileserver\share\results.csv
```

## Offline checking (Linux)

Download `downloads/impacted-intermediates.json`, then verify each chain against your local trust store with OpenSSL, or simply probe from the shell:

```bash
for h in dv-g3b ov-g3b ev-g3b dv-g3c ov-g3c ev-g3c; do
  for p in "" "-aaa"; do
    host="${h}${p}-emudhra.we-have-a-problem.com"
    if curl -s -o /dev/null --max-time 10 "https://$host/"; then
      echo "❌ $host — CONNECTED (still trusted!)"
    else
      echo "✅ $host — blocked (curl exit $?)"
    fi
  done
done
```

## Notes & caveats

- Layers can disagree; trust order: **live TLS probe > Disallowed CTL > version heuristics**.
- Firefox uses its own trust store + CRLite and is not covered by the Windows Disallowed CTL check — verify it with the live page.
- The 4 code-signing intermediates (EM OV CS CA - G3B/G3C) are included in the fingerprint comparison for forged-binary risk assessment.
- Remediation: latest OS cumulative updates and browser versions; dev toolchains NSS ≥ 3.131.1, certifi ≥ 2026.10.19, Node.js ≥ 22.23.4, Go ≥ 1.26.10, etc. Full list on the original site.

## Data sources

- Disclosure & test domains: https://emudhra.we-have-a-problem.com/
- Certificate list: https://emudhra.we-have-a-problem.com/impacted-intermediates.json (vendored in `public/downloads/`)
- Mozilla incident report: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449

## License

MIT
