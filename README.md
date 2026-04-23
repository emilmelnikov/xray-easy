# xray-easy

`xray-easy` is a small Go wrapper around `xray-core` for a specific deployment model:

- one main node with one public VLESS + REALITY + Vision inbound
- optional out nodes that accept relay traffic from the main node
- user data stored only on the main node in `users.json`
- per-user profile and subscription pages served through the REALITY fallback HTTP target

## Commands

Initialize a new main node:

```bash
xray-easy init-config \
  -output config.json \
  -users-output users.json \
  -listen :443 \
  -public-host main.example.com \
  -server-name www.cloudflare.com
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
  -server-name www.cloudflare.com \
  relay-de > relay-config.json
```

Then run the out node:

```bash
xray-easy serve -config relay-config.json
```

## Config Files

Main node `config.json`:

```json
{
  "role": "main",
  "httpListen": "127.0.0.1:8080",
  "inbound": {
    "listen": ":443",
    "publicHost": "main.example.com",
    "serverName": "www.cloudflare.com",
    "privateKey": "...",
    "shortId": "..."
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
  "httpListen": "127.0.0.1:8080",
  "inbound": {
    "listen": ":443",
    "serverName": "www.cloudflare.com",
    "privateKey": "...",
    "shortId": "...",
    "relayUUID": "..."
  }
}
```

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
