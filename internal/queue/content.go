package queue

// The private storage format is a Merkle tree of JSON fragments and binary
// chunks. Public event JSON is reconstructed, never sent with references.
import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"sort"
	"strings"
)

const chunkBytes = 4096
const maxObjectBytes = 16 << 20

type fragment struct {
	JSON json.RawMessage `json:"j,omitempty"`
	Ref  string          `json:"r,omitempty"`
}
type member struct {
	Key   string   `json:"k"`
	Value fragment `json:"v"`
}
type contentNode struct {
	Kind   string     `json:"k"`
	Data   []byte     `json:"d,omitempty"`
	Fields []member   `json:"f,omitempty"`
	Items  []fragment `json:"a,omitempty"`
	Chunks []string   `json:"c,omitempty"`
}
type manifest struct {
	Version int    `json:"_ta_storage"`
	Root    string `json:"root"`
}
type sqlReader interface{ QueryRow(string, ...any) *sql.Row }

// Scoped to one restoration, not historical database size.
type contentReader struct {
	sqlReader
	cache map[string][]byte
	bytes int
}
type objectWriter struct {
	tx    *sql.Tx
	known map[string][]byte
}

func pack(raw []byte) (int, []byte, error) {
	if len(raw) < 256 {
		return 0, raw, nil
	}
	var b bytes.Buffer
	w, err := zlib.NewWriterLevel(&b, zlib.BestSpeed)
	if err != nil {
		return 0, nil, err
	}
	if _, err = w.Write(raw); err != nil {
		return 0, nil, err
	}
	if err = w.Close(); err != nil {
		return 0, nil, err
	}
	if b.Len() >= len(raw) {
		return 0, raw, nil
	}
	return 1, b.Bytes(), nil
}
func unpack(codec, size int, data []byte) ([]byte, error) {
	if size < 0 || size > maxObjectBytes {
		return nil, fmt.Errorf("invalid content size %d", size)
	}
	if codec == 0 {
		if len(data) != size {
			return nil, fmt.Errorf("content size mismatch")
		}
		return data, nil
	}
	if codec != 1 {
		return nil, fmt.Errorf("unsupported content codec %d", codec)
	}
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, int64(size)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) != size {
		return nil, fmt.Errorf("decompressed content size mismatch")
	}
	return raw, nil
}
func readObject(db sqlReader, id string) ([]byte, error) {
	if cached, ok := db.(*contentReader); ok {
		if raw, ok := cached.cache[id]; ok {
			return raw, nil
		}
		raw, err := readObject(cached.sqlReader, id)
		if err == nil && cached.bytes+len(raw) <= 8<<20 {
			cached.cache[id] = raw
			cached.bytes += len(raw)
		}
		return raw, err
	}
	var codec, size int
	var data []byte
	if err := db.QueryRow("SELECT codec,size,data FROM queue_content WHERE hash=?", id).Scan(&codec, &size, &data); err != nil {
		return nil, fmt.Errorf("read content %s: %w", id, err)
	}
	raw, err := unpack(codec, size, data)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != id {
		return nil, fmt.Errorf("content checksum mismatch: %s", id)
	}
	return raw, nil
}
func nodeRefs(n contentNode) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, f := range n.Fields {
		add(f.Value.Ref)
	}
	for _, f := range n.Items {
		add(f.Ref)
	}
	for _, s := range n.Chunks {
		add(s)
	}
	return out
}
func decodeNode(raw []byte, n *contentNode) error {
	if len(raw) > 0 && raw[0] == 0 {
		n.Kind = "bytes"
		n.Data = raw[1:]
		return nil
	}
	return json.Unmarshal(raw, n)
}
func (w *objectWriter) save(n contentNode) (fragment, error) {
	raw, err := json.Marshal(n)
	if n.Kind == "bytes" {
		raw = append([]byte{0}, n.Data...)
		err = nil
	}
	if err != nil {
		return fragment{}, err
	}
	if len(raw) > maxObjectBytes {
		return fragment{}, fmt.Errorf("content node exceeds storage bound")
	}
	sum := sha256.Sum256(raw)
	id := hex.EncodeToString(sum[:])
	if b, ok := w.known[id]; ok {
		if !bytes.Equal(b, raw) {
			return fragment{}, fmt.Errorf("content hash collision")
		}
		return fragment{Ref: id}, nil
	}
	old, err := readObject(w.tx, id)
	if err == nil {
		if !bytes.Equal(old, raw) {
			return fragment{}, fmt.Errorf("content hash collision")
		}
	} else {
		if !isMissing(err) {
			return fragment{}, err
		}
		codec, data, err := pack(raw)
		if err != nil {
			return fragment{}, err
		}
		if _, err = w.tx.Exec("INSERT INTO queue_content(hash,codec,size,data) VALUES(?,?,?,?)", id, codec, len(raw), data); err != nil {
			return fragment{}, err
		}
		for _, child := range nodeRefs(n) {
			if _, err = w.tx.Exec("INSERT INTO queue_edges(parent,child) VALUES(?,?)", id, child); err != nil {
				return fragment{}, err
			}
		}
	}
	// Per-event cache: no history-sized process-global cache.
	w.known[id] = raw
	return fragment{Ref: id}, nil
}
func (w *objectWriter) stringValue(s, key string) (fragment, error) {
	if len(s) < 128 {
		b, err := json.Marshal(s)
		return fragment{JSON: b}, err
	}
	kind := "string"
	data := []byte(s)
	if strings.HasSuffix(key, "_hex") {
		if b, err := hex.DecodeString(s); err == nil && hex.EncodeToString(b) == s {
			kind = "hex"
			data = b
		}
	}
	var chunks []string
	for len(data) > 0 {
		n := len(data)
		if n > chunkBytes {
			n = chunkBytes
		}
		f, err := w.save(contentNode{Kind: "bytes", Data: data[:n]})
		if err != nil {
			return fragment{}, err
		}
		chunks = append(chunks, f.Ref)
		data = data[n:]
	}
	return w.save(contentNode{Kind: kind, Chunks: chunks})
}
func emptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.Interface, reflect.Pointer:
		return v.IsZero()
	}
	return false
}
func (w *objectWriter) encode(v reflect.Value, key string) (fragment, error) {
	if !v.IsValid() {
		return fragment{JSON: json.RawMessage("null")}, nil
	}
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return fragment{JSON: json.RawMessage("null")}, nil
		}
		v = v.Elem()
	}
	// Respect custom JSON serializers (RawMessage, time.Time, json.Number...).
	if v.CanInterface() {
		if number, ok := v.Interface().(json.Number); ok {
			b, err := json.Marshal(number)
			return fragment{JSON: b}, err
		}
		if _, ok := v.Interface().(json.Marshaler); ok {
			b, err := json.Marshal(v.Interface())
			return fragment{JSON: b}, err
		}
	}
	var n contentNode
	switch v.Kind() {
	case reflect.String:
		return w.stringValue(v.String(), key)
	case reflect.Struct:
		n.Kind = "object"
		typ := v.Type()
		for i := 0; i < v.NumField(); i++ {
			sf := typ.Field(i)
			if sf.PkgPath != "" {
				continue
			}
			tag := strings.Split(sf.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = sf.Name
			}
			omit := false
			for _, opt := range tag[1:] {
				if opt == "omitempty" {
					omit = true
				}
			}
			if omit && emptyValue(v.Field(i)) {
				continue
			}
			f, err := w.encode(v.Field(i), name)
			if err != nil {
				return fragment{}, err
			}
			n.Fields = append(n.Fields, member{name, f})
		}
	case reflect.Map:
		if v.IsNil() {
			return fragment{JSON: json.RawMessage("null")}, nil
		}
		if v.Type().Key().Kind() != reflect.String {
			b, err := json.Marshal(v.Interface())
			return fragment{JSON: b}, err
		}
		n.Kind = "object"
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, k := range keys {
			f, err := w.encode(v.MapIndex(k), k.String())
			if err != nil {
				return fragment{}, err
			}
			n.Fields = append(n.Fields, member{k.String(), f})
		}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return fragment{JSON: json.RawMessage("null")}, nil
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b, err := json.Marshal(v.Interface())
			return fragment{JSON: b}, err
		}
		n.Kind = "array"
		for i := 0; i < v.Len(); i++ {
			f, err := w.encode(v.Index(i), key)
			if err != nil {
				return fragment{}, err
			}
			n.Items = append(n.Items, f)
		}
	default:
		b, err := json.Marshal(v.Interface())
		return fragment{JSON: b}, err
	}
	// Small containers with no references are cheaper inline.
	if len(nodeRefs(n)) == 0 {
		b, err := json.Marshal(v.Interface())
		if err != nil {
			return fragment{}, err
		}
		if len(b) < 512 {
			return fragment{JSON: b}, nil
		}
	}
	return w.save(n)
}
func encodePayload(tx *sql.Tx, value any) (string, error) {
	w := objectWriter{tx: tx, known: map[string][]byte{}}
	f, err := w.encode(reflect.ValueOf(value), "")
	if err != nil {
		return "", err
	}
	if f.Ref == "" {
		f, err = w.save(contentNode{Kind: "json", Data: f.JSON})
		if err != nil {
			return "", err
		}
	}
	b, err := json.Marshal(manifest{2, f.Ref})
	return string(b), err
}
func payloadRoot(payload string) (string, error) {
	var m manifest
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		return "", err
	}
	if m.Version == 0 {
		return "", nil
	}
	if m.Version != 2 || len(m.Root) != 64 {
		return "", fmt.Errorf("unsupported queue storage manifest")
	}
	return m.Root, nil
}
func decodePayload(db sqlReader, payload string) ([]byte, error) {
	root, err := payloadRoot(payload)
	if err != nil {
		return nil, err
	}
	if root == "" {
		return []byte(payload), nil
	}
	var out bytes.Buffer
	reader := &contentReader{sqlReader: db, cache: map[string][]byte{}}
	if err := render(reader, &out, fragment{Ref: root}, map[string]bool{}, 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func render(db sqlReader, out *bytes.Buffer, f fragment, visiting map[string]bool, depth int) error {
	if f.Ref == "" {
		if !json.Valid(f.JSON) {
			return fmt.Errorf("invalid inline JSON")
		}
		out.Write(f.JSON)
		return nil
	}
	if depth > 256 || visiting[f.Ref] {
		return fmt.Errorf("cyclic or excessive content nesting")
	}
	visiting[f.Ref] = true
	defer delete(visiting, f.Ref)
	raw, err := readObject(db, f.Ref)
	if err != nil {
		return err
	}
	var n contentNode
	if err = decodeNode(raw, &n); err != nil {
		return err
	}
	switch n.Kind {
	case "json":
		if !json.Valid(n.Data) {
			return fmt.Errorf("invalid JSON content")
		}
		out.Write(n.Data)
	case "object":
		out.WriteByte('{')
		for i, m := range n.Fields {
			if i > 0 {
				out.WriteByte(',')
			}
			k, _ := json.Marshal(m.Key)
			out.Write(k)
			out.WriteByte(':')
			if err = render(db, out, m.Value, visiting, depth+1); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case "array":
		out.WriteByte('[')
		for i, v := range n.Items {
			if i > 0 {
				out.WriteByte(',')
			}
			if err = render(db, out, v, visiting, depth+1); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case "string", "hex":
		var b bytes.Buffer
		for _, id := range n.Chunks {
			raw, err := readObject(db, id)
			if err != nil {
				return err
			}
			var c contentNode
			if err = decodeNode(raw, &c); err != nil {
				return err
			}
			if c.Kind != "bytes" || len(c.Data) > chunkBytes {
				return fmt.Errorf("invalid binary chunk")
			}
			b.Write(c.Data)
		}
		s := b.String()
		if n.Kind == "hex" {
			s = hex.EncodeToString(b.Bytes())
		}
		encoded, _ := json.Marshal(s)
		out.Write(encoded)
	default:
		return fmt.Errorf("invalid content node %q", n.Kind)
	}
	return nil
}
