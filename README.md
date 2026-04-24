# xray-easy

`xray-easy` is a small Go wrapper around `xray-core` for a specific deployment model:

- one main node with one public VLESS + REALITY + Vision inbound
- optional out nodes that accept relay traffic from the main node
- user data stored only on the main node in `users.json`
- per-user profile and subscription pages served through the REALITY fallback HTTPS target

## Commands

Initialize a new main node:

```bash
xray-easy init-config \
  -output config.json \
  -users-output users.json \
  -server-name main.example.com
```

Run a node:

```bash
xray-easy serve -config config.json -users users.json
```

Add a user on the main node:

```bash
xray-easy add-user -config config.json -users users.json alice
```

Add a relay route on the main node and print the out-node config to stdout:

```bash
xray-easy add-route \
  -config config.json \
  -users users.json \
  -address relay.example.com \
  -port 443 \
  relay-de > relay-config.json
```

Then run the out node:

```bash
xray-easy serve -config relay-config.json
```

## Build

Build release-style binaries locally with GoReleaser:

```bash
goreleaser build --snapshot --clean
```

This uses `.goreleaser.yaml` and writes artifacts under `dist/`. Install GoReleaser with:

```bash
go install github.com/goreleaser/goreleaser/v2@latest
```

Pushing a tag matching `v*` runs the release workflow. It tests the module, then GoReleaser builds Linux `amd64` and `arm64` binaries, writes `checksums.txt`, signs that checksum file with Cosign keyless signing, and publishes a GitHub Release with those assets.

## Cloud Init

The cloud-init example lives in `contrib/cloud-init/xray-easy.yaml`. It prepares a fresh systemd host by:

- installing `ca-certificates` and `curl`
- downloading the latest GitHub Releases binary to `/usr/local/bin/xray-easy`
- installing `/usr/local/sbin/update-xray-easy`
- creating the `xray-easy` user/group
- creating `/etc/xray-easy`
- installing `/etc/systemd/system/xray-easy.service`
- installing `/etc/default/xray-easy`
- enabling the service

The release assets are expected to be named:

- `xray-easy-linux-amd64`
- `xray-easy-linux-arm64`

The generated unit assumes:

- binary: `/usr/local/bin/xray-easy`
- config directory: `/etc/xray-easy`
- config file: `/etc/xray-easy/config.json`
- users file: `/etc/xray-easy/users.json`
- runtime user/group: `xray-easy`

Optional service overrides can be placed in `/etc/default/xray-easy`:

```sh
XRAY_EASY_CONFIG=/etc/xray-easy/config.json
XRAY_EASY_USERS=/etc/xray-easy/users.json
```

Out nodes can use the same unit. The `-users` path is ignored when `config.json` has `"role": "out"`.

The unit grants `CAP_NET_BIND_SERVICE` so the service user can bind ports below 1024.

The cloud-init example enables but does not start the service because `config.json` and, for main nodes, `users.json` still need to be installed.

Update an installed node to the latest release with:

```bash
sudo /usr/local/sbin/update-xray-easy
```

To install a specific release instead, pass `XRAY_EASY_VERSION`:

```bash
sudo XRAY_EASY_VERSION=v0.1.1 /usr/local/sbin/update-xray-easy
```

## Config Files

Main node `config.json`:

```json
{
  "role": "main",
  "http_listen": "127.0.0.1:8080",
  "loglevel": "warning",
  "certificate": {
    "cache_dir": "certs",
    "ca_dir_url": "https://acme-v02.api.letsencrypt.org/directory"
  },
  "inbound": {
    "server_name": "main.example.com",
    "private_key": "...",
    "short_id": "..."
  },
  "routes": [
    {
      "id": 1234,
      "name": "local",
      "title": "local",
      "outbound": {
        "type": "freedom"
      }
    }
  ]
}
```

Out node `config.json`:

```json
{
  "role": "out",
  "loglevel": "warning",
  "inbound": {
    "server_name": "main.example.com",
    "dest": "main.example.com:443",
    "private_key": "...",
    "short_id": "...",
    "relay_uuid": "..."
  }
}
```

For the main node steal-oneself setup, `inbound.server_name` must be a domain you control that reaches the main node's public `:443`. The same value is used for REALITY SNI, generated profile URLs, and the managed certificate.

`inbound.listen` is optional and defaults to `:443`.

Main nodes also listen on `certificate.http_listen` for HTTP-01 certificate challenges. `/.well-known/acme-challenge/*` is served for ACME validation; all other HTTP requests redirect to HTTPS. `certificate.http_listen` is optional and defaults to `:80`, so public TCP ports `80` and `443` must both reach the main node.

Out nodes do not serve profile pages and do not manage certificates. Their `inbound.dest` is the main node public address, and `inbound.server_name` is the main node REALITY SNI.

Users live only on the main node:

```json
{
  "users": [
    {
      "username": "alice",
      "token": "...",
      "clients": [
        {
          "route": "local",
          "uuid": "..."
        }
      ]
    }
  ]
}
```

Each client UUID embeds the route id in bytes `6:8`, and `xray-easy` validates that mapping before starting.
