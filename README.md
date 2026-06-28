# LocalToGlobal

LocalToGlobal is a CLI-first developer tool that detects local apps, applies safe sharing defaults, and exposes them through Cloudflare Quick Tunnels.

## Commands

```bash
cargo run -- run
cargo run -- share
cargo run -- routes init
cargo run -- protect --expires-in 30m --access-mode token
cargo run -- status
```

## Config

The CLI keeps a project-aware config in `.localtoglobal.yml` and runtime state under `.localtoglobal/`.

## Notes

- `share` starts a small local guard proxy that enforces expiry and optional share tokens before forwarding to your real local app.
- `status` summarizes active shares by reading the persisted runtime state and access logs.
- Route profiles let you publish multiple local services behind one Cloudflare URL by matching path prefixes.
