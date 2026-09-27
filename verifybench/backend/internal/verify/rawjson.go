package verify

import "encoding/json"

// RawJSON is a byte slice that is embedded verbatim in JSON output when it
// already contains valid JSON; otherwise (e.g. malformed uploaded evidence)
// it is serialized as an ordinary JSON string, so the API response itself is
// always valid JSON.
type RawJSON []byte

// MarshalJSON implements json.Marshaler.
func (r RawJSON) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("null"), nil
	}
	if json.Valid(r) {
		return r, nil
	}
	return json.Marshal(string(r))
}

// Scan implements sql.Scanner for database round-trips.
func (r *RawJSON) Scan(src interface{}) error {
	switch v := src.(type) {
	case []byte:
		*r = append((*r)[:0], v...)
	case string:
		*r = RawJSON(v)
	case nil:
		*r = nil
	}
	return nil
}
