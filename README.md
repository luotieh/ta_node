# ta_node

`ta_node` is a Go all-in-one traffic analysis node that combines packet capture, protocol parsing, payload fingerprint rules, threat-intel matching, local event durability, and management push.

## Build

```bash
go mod tidy
go build ./cmd/ta_node
```

Live interface capture defaults to Linux AF_PACKET and does not require libpcap headers. On systems where you explicitly want the libpcap backend, build it with:

```bash
go build -tags pcap -o ta_node ./cmd/ta_node
```

## Run

Offline pcap:

```bash
./ta_node --config ./configs/ta_node.yaml --pcap-file ./test.pcap
```

Live capture:

```bash
sudo ./ta_node --config ./configs/ta_node.yaml --interface eth0
```

Intel CLI:

```bash
./ta_node --config ./configs/ta_node.yaml intel add --type ip --value 1.2.3.4 --category c2 --severity high
./ta_node --config ./configs/ta_node.yaml intel list
./ta_node --config ./configs/ta_node.yaml intel delete --id ioc-001
./ta_node --config ./configs/ta_node.yaml intel reload
```

Local intel API listens on `server.listen`:

```bash
curl -X POST http://127.0.0.1:19090/api/v1/intel \
  -H 'Content-Type: application/json' \
  -d '{"type":"domain","value":"evil.example.com","category":"c2","severity":"critical","enabled":true}'
```

Threat Intel Hub should prefer source-scoped sync so local IOC are preserved:

```bash
curl -X POST http://127.0.0.1:19090/api/v1/intel/sync-source \
  -H 'Authorization: Bearer <server.token>' \
  -H 'Content-Type: application/json' \
  -d '{"source":"Threat Intel Hub","items":[{"id":"hub-ip-1.2.3.4","type":"ip","value":"1.2.3.4","category":"c2","severity":"high","enabled":true}]}'
```

Incremental updates and lightweight STIX/TAXII Envelope ingestion are also available:

```text
POST /api/v1/intel/batch-upsert
POST /api/v1/intel/stix?source=Threat%20Intel%20Hub
GET  /api/v1/intel/stats
GET  /api/v1/health
```

Open the deployment configuration page at:

```text
http://127.0.0.1:19090/config
```

On machines where live capture privileges are not available yet, start only the config service:

```bash
./ta_node --config ./configs/ta_node.yaml --config-only
```

The page writes back to the `--config` file. Capture and push settings take effect after restarting `ta_node`.

Events are persisted in SQLite before push. When the management endpoint is unavailable, pending events remain in `event_queue` and are retried by the push worker.

For exposed deployments, set `server.token` and send `Authorization: Bearer <token>` on write APIs, or bind `server.listen` to `127.0.0.1` behind a TLS reverse proxy.

## ARM Offline Deployment

Supported targets:

```text
Linux arm64
Linux armv7
```

Prepare dependencies in an online development environment:

```bash
go mod tidy
go mod vendor
go mod verify
```

Build offline ARM binaries:

```bash
./scripts/build-all-offline.sh
```

Package the offline release:

```bash
./scripts/package-offline.sh
```

Install on an ARM64 machine:

```bash
tar -xzf ta_node-offline-*.tar.gz
cd ta_node-offline-*
sudo ./deploy/install-offline.sh arm64
```

Install on an ARMv7 machine:

```bash
tar -xzf ta_node-offline-*.tar.gz
cd ta_node-offline-*
sudo ./deploy/install-offline.sh armv7
```

Manage the service:

```bash
sudo systemctl status ta_node
sudo journalctl -u ta_node -f
sudo systemctl restart ta_node
```

The offline config is `configs/ta_node.offline.yaml`. It disables event push by default and binds the local config service to `127.0.0.1:19090`. For remote access to the config page, set a strong `server.token` and configure your firewall or reverse proxy explicitly.

The default ARM offline build uses Linux AF_PACKET and does not use `-tags pcap`. In this mode, keep `capture.bpf_filter` empty. If BPF filter support is required, build a separate `-tags pcap` version and provide the target ARM libpcap development libraries. The pcap build is an optional advanced path and is not part of the default offline package.
