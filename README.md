# ta_node

`ta_node` is a Go all-in-one traffic analysis node that combines packet capture, protocol parsing, payload fingerprint rules, threat-intel matching, local event durability, and management push.

## Build

```bash
go mod tidy
go build ./cmd/ta_node
```

Live interface capture uses libpcap. On systems with libpcap headers installed, build it with:

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

Events are persisted in SQLite before push. When the management endpoint is unavailable, pending events remain in `event_queue` and are retried by the push worker.
