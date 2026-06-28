# LocalToGlobal

LocalToGlobal is a CLI-first developer tool that detects local apps, applies safe sharing defaults, and exposes them through Cloudflare Quick Tunnels.

## Install

Normal users do not need Rust or Cargo. Install the latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/MananxRobin/localToGlobal/main/install.sh | sh
```

The installer downloads the right `ltg` binary for macOS/Linux and runs `ltg doctor`. If `cloudflared` is missing, `ltg` installs a managed copy under `~/.local/share/localtoglobal/bin/`.

If `ltg` is not found after install, add this to your shell profile:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Quick Start

Start your local app, then share it:

```bash
ltg share 3000
```

Or let LocalToGlobal detect local HTTP services first:

```bash
ltg run
ltg share
```

Run a dependency check anytime:

```bash
ltg doctor
```

## Commands

```bash
ltg run
ltg share
ltg routes init
ltg protect --expires-in 30m --access-mode token
ltg status
ltg doctor
```

## Config

The CLI keeps a project-aware config in `.localtoglobal.yml` and runtime state under `.localtoglobal/`.

## Notes

- `share` starts a small local guard proxy that enforces expiry and optional share tokens before forwarding to your real local app.
- `status` summarizes active shares by reading the persisted runtime state and access logs.
- Route profiles let you publish multiple local services behind one Cloudflare URL by matching path prefixes.

## Develop From Source

Install Rust only if you want to work on LocalToGlobal itself:

```bash
git clone https://github.com/MananxRobin/localToGlobal.git
cd localToGlobal
cargo test
cargo run -- share 3000
```
