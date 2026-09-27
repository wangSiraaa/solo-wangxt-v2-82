package store

import "encoding/json"

// jsonb returns the bytes as-is for a JSONB parameter, defaulting to "null".
func jsonb(b []byte) []byte {
	if len(b) == 0 {
		return []byte("null")
	}
	return b
}

// jsonbOrNull returns nil (SQL NULL) when the payload is empty or JSON null.
func jsonbOrNull(b []byte) interface{} {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return b
}

// mustJSON marshals v, falling back to "null" on error (values here are
// always marshalable: structs/maps of plain data).
func mustJSON(v interface{}) []byte {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}

func jsonUnmarshal(b []byte, v interface{}) error { return json.Unmarshal(b, v) }
