# ccproxy

Closed Code Proxy liberates your subscription. Reverse proxy that handles auth, token refresh, and fingerprint normalization so you can use your plan however you want.

## Quick Start

### 1. Create `compose.yml`

```yaml
services:
  default:
    image: ghcr.io/saucesteals/ccproxy:latest
    ports:
      - "127.0.0.1:9191:8080"
    volumes:
      - ./profiles/default:/data
    environment:
      # AUTH_TOKEN gates access to ccproxy itself (sent as `x-api-key`).
      # It is NOT your upstream subscription token — ccproxy handles that
      # internally via OAuth. Leave unset to accept any key.
      # - AUTH_TOKEN=my-secret-token
      - CONFIG_DIR=/data
    restart: unless-stopped
```

### 2. Run

```bash
docker compose up -d
```

### 3. Authenticate

Check auth status (any `x-api-key` works when `AUTH_TOKEN` is unset):

```bash
curl -s -H 'x-api-key: anything' http://localhost:9191/_auth
```

If not authenticated, you'll get an OAuth URL. Open it, log in, and you'll receive a `code#state` value. POST it back:

```bash
curl -s -X POST -H 'x-api-key: anything' http://localhost:9191/_auth -d 'CODE#STATE'
```

Tokens auto-refresh from here.

### 4. Verify

```bash
curl -s http://localhost:9191/_health
```

## API

- `GET /_health` — status, upstream, version (no auth)
- `GET /_auth` — current auth status or OAuth URL
- `POST /_auth` — complete auth (body: `code#state`)
- `DELETE /_auth` — logout
- `* /*` — proxied upstream

All endpoints except `/_health` require an `x-api-key` header. When `AUTH_TOKEN` is set, the header value must match it; when unset, any value (including empty) is accepted.

## Multiple Profiles

```yaml
services:
  alice:
    image: ghcr.io/saucesteals/ccproxy:latest
    ports:
      - "127.0.0.1:9191:8080"
    volumes:
      - ./profiles/alice:/data
    environment:
      - AUTH_TOKEN=alice-token
      - CONFIG_DIR=/data
    restart: unless-stopped

  bob:
    image: ghcr.io/saucesteals/ccproxy:latest
    ports:
      - "127.0.0.1:9192:8080"
    volumes:
      - ./profiles/bob:/data
    environment:
      - AUTH_TOKEN=bob-token
      - CONFIG_DIR=/data
    restart: unless-stopped
```

Authenticate each profile separately via its port.

## Environment Variables

- **`AUTH_TOKEN`** — shared secret for client auth (`x-api-key` header). Gates access to ccproxy itself, **not** your upstream subscription. Leave unset to accept any key.
- **`CONFIG_DIR`** — data directory (default: `~/.ccproxy`)
- **`CC_VERSION`** — client version string (default: `2.1.92`)
- **`UPSTREAM`** — upstream API endpoint
- **`LISTEN_ADDR`** — listen address (default: `:8080`)

## License

MIT
