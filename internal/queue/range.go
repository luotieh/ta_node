package queue

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type PacketRange struct {
	Offset           int    `json:"offset"`
	Length           int    `json:"length"`
	TotalLength      int    `json:"total_length"`
	PacketHex        string `json:"packet_hex"`
	CaptureTruncated bool   `json:"capture_truncated"`
}

// child selects one JSON member without expanding other evidence nodes.
func child(db sqlReader, f fragment, key string) (fragment, error) {
	if f.Ref != "" {
		raw, err := readObject(db, f.Ref)
		if err != nil {
			return fragment{}, err
		}
		var n contentNode
		if err = decodeNode(raw, &n); err != nil {
			return fragment{}, err
		}
		if n.Kind == "object" {
			for _, m := range n.Fields {
				if m.Key == key {
					return m.Value, nil
				}
			}
			return fragment{}, sql.ErrNoRows
		}
		if n.Kind != "json" {
			return fragment{}, fmt.Errorf("expected JSON object")
		}
		f.JSON = n.Data
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(f.JSON, &obj); err != nil {
		return fragment{}, err
	}
	v, ok := obj[key]
	if !ok {
		return fragment{}, sql.ErrNoRows
	}
	return fragment{JSON: v}, nil
}
func rangeFromPayload(db sqlReader, payload string, offset, length int) (PacketRange, error) {
	out := PacketRange{Offset: offset}
	root, err := payloadRoot(payload)
	if err != nil {
		return out, err
	}
	f := fragment{Ref: root}
	if root == "" {
		f.JSON = json.RawMessage(payload)
	}
	raw, err := child(db, f, "raw_packet")
	if err != nil {
		return out, err
	}
	if truncated, e := child(db, raw, "capture_truncated"); e == nil {
		var b bytes.Buffer
		if e = render(db, &b, truncated, map[string]bool{}, 0); e != nil {
			return out, e
		}
		if e = json.Unmarshal(b.Bytes(), &out.CaptureTruncated); e != nil {
			return out, e
		}
	} else if !isMissing(e) {
		return out, e
	}
	field, err := child(db, raw, "packet_hex")
	if err != nil {
		return out, err
	}
	var data []byte
	if field.Ref != "" {
		encoded, e := readObject(db, field.Ref)
		if e != nil {
			return out, e
		}
		var n contentNode
		if e = decodeNode(encoded, &n); e != nil {
			return out, e
		}
		if n.Kind == "hex" {
			total := 0
			for _, id := range n.Chunks {
				// Binary chunks are canonical: one kind byte followed by packet bytes.
				var size int
				if e = db.QueryRow("SELECT size FROM queue_content WHERE hash=?", id).Scan(&size); e != nil {
					return out, e
				}
				nbytes := size - 1
				if nbytes < 0 || nbytes > chunkBytes {
					return out, fmt.Errorf("invalid chunk size")
				}
				if offset < total+nbytes && offset+length > total {
					b, e := readObject(db, id)
					if e != nil {
						return out, e
					}
					var c contentNode
					if e = decodeNode(b, &c); e != nil {
						return out, e
					}
					if c.Kind != "bytes" {
						return out, fmt.Errorf("invalid binary chunk")
					}
					lo := offset - total
					if lo < 0 {
						lo = 0
					}
					hi := offset + length - total
					if hi > len(c.Data) {
						hi = len(c.Data)
					}
					data = append(data, c.Data[lo:hi]...)
				}
				total += nbytes
			}
			if offset > total {
				return out, fmt.Errorf("offset exceeds packet length")
			}
			out.TotalLength = total
			out.Length = len(data)
			out.PacketHex = hex.EncodeToString(data)
			return out, nil
		}
	}
	var b bytes.Buffer
	if err = render(db, &b, field, map[string]bool{}, 0); err != nil {
		return out, err
	}
	var s string
	if err = json.Unmarshal(b.Bytes(), &s); err != nil {
		return out, err
	}
	data, err = hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if offset > len(data) {
		return out, fmt.Errorf("offset exceeds packet length")
	}
	end := offset + length
	if end > len(data) {
		end = len(data)
	}
	out.TotalLength = len(data)
	out.Length = end - offset
	out.PacketHex = hex.EncodeToString(data[offset:end])
	return out, nil
}

// ReadPacketRange locates the event in whichever shard holds it; pre-sharding
// rows live in the base file, so every shard file is tried in turn.
func ReadPacketRange(path, key string, offset, length int) (PacketRange, error) {
	var last error
	for _, p := range shardPaths(path) {
		result, err := readPacketRangeOne(p, key, offset, length)
		if isMissing(err) {
			last = err
			continue
		}
		return result, err
	}
	if last != nil {
		return PacketRange{}, last
	}
	return PacketRange{}, sql.ErrNoRows
}

func readPacketRangeOne(path, key string, offset, length int) (PacketRange, error) {
	if offset < 0 || length < 1 || length > 65536 || offset > int(^uint(0)>>1)-length {
		return PacketRange{}, fmt.Errorf("invalid range")
	}
	db, err := readOnly(path)
	if err != nil {
		return PacketRange{}, err
	}
	defer db.Close()
	read := func(db *sql.DB) (PacketRange, error) {
		tx, e := db.Begin()
		if e != nil {
			return PacketRange{}, e
		}
		defer tx.Rollback()
		var p string
		if e = tx.QueryRow("SELECT payload FROM event_queue WHERE event_id=?", key).Scan(&p); e != nil {
			return PacketRange{}, e
		}
		return rangeFromPayload(tx, p, offset, length)
	}
	result, err := read(db)
	if !isMissing(err) {
		return result, err
	}
	var exists int
	if e := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='queue_archived'").Scan(&exists); e != nil {
		return result, e
	}
	if exists == 0 {
		return result, err
	}
	var archive string
	if e := db.QueryRow("SELECT path FROM queue_archived WHERE event_id=?", key).Scan(&archive); e != nil {
		return result, e
	}
	adb, e := readOnly(archive)
	if e != nil {
		return result, e
	}
	defer adb.Close()
	return read(adb)
}
