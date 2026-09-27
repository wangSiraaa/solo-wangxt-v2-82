// Package demo embeds the three fixed demo scenarios so the server can serve
// them without depending on the working directory.
package demo

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed demodata/*
var fs embed.FS

// Scenario is demo metadata.
type Scenario struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	ArtifactFile   string   `json:"artifactFile"`
	ExpectedAllow  bool     `json:"expectedAllow"`
	ExpectedChecks []string `json:"expectedChecks"`
}

type manifest struct {
	Scenarios []Scenario `json:"scenarios"`
}

var byID = func() map[string]Scenario {
	data, err := fs.ReadFile("demodata/demo.json")
	if err != nil {
		panic("embedded demo manifest missing: " + err.Error())
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		panic(err)
	}
	out := make(map[string]Scenario, len(m.Scenarios))
	for _, s := range m.Scenarios {
		out[s.ID] = s
	}
	return out
}()

// Scenarios returns the three scenarios in fixed order.
func Scenarios() []Scenario {
	return []Scenario{byID["normal"], byID["tampered"], byID["untrusted"]}
}

// Get returns one scenario by id.
func Get(id string) (Scenario, error) {
	s, ok := byID[id]
	if !ok {
		return Scenario{}, fmt.Errorf("unknown demo scenario %q", id)
	}
	return s, nil
}

// Artifact returns the raw demo artifact bytes.
func Artifact(id string) ([]byte, error) {
	if _, err := Get(id); err != nil {
		return nil, err
	}
	return fs.ReadFile("demodata/" + id + "/artifact.txt")
}

// Envelope returns the demo DSSE envelope JSON.
func Envelope(id string) ([]byte, error) {
	if _, err := Get(id); err != nil {
		return nil, err
	}
	return fs.ReadFile("demodata/" + id + "/envelope.json")
}

// TrustRoot returns the demo trust root JSON.
func TrustRoot() []byte {
	data, err := fs.ReadFile("demodata/trust-root.json")
	if err != nil {
		panic(err)
	}
	return data
}
