// Package trust loads the trust root: the set of allowed builder signing keys
// together with their builder ids. Only keys present here can make a
// signature count as trusted by the policy.
package trust

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/example/verifybench/internal/dsse"
)

// Config is the on-disk trust root format.
type Config struct {
	Version int          `json:"version"`
	Keys    []TrustedKey `json:"keys"`
	// AllowedSourceHosts restricts buildDefinition.resolvedDependencies git
	// URIs. A build sourced from github.com/malicious is rejected.
	AllowedSourceHosts []string `json:"allowedSourceHosts"`
	// AllowedBuildTypes restricts buildDefinition.buildType.
	AllowedBuildTypes []string `json:"allowedBuildTypes"`
}

// TrustedKey is one ed25519 key mapped to a builder id.
type TrustedKey struct {
	KeyID        string `json:"keyId"`
	BuilderID    string `json:"builderId"`
	PublicKeyPEM string `json:"publicKeyPem"`
}

// Root is the parsed trust root plus a key ring for verification.
type Root struct {
	Config Config
	Ring   map[string]dsse.PublicKey
	// ByBuilder maps builderId -> trusted key.
	ByBuilder map[string]dsse.PublicKey
}

// LoadFile reads and parses a trust root JSON file.
func LoadFile(path string) (*Root, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust root: %w", err)
	}
	return Load(data)
}

// Load parses a trust root from bytes.
func Load(data []byte) (*Root, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse trust root: %w", err)
	}
	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("trust root contains no keys")
	}
	ring := make(map[string]dsse.PublicKey, len(cfg.Keys))
	byBuilder := make(map[string]dsse.PublicKey, len(cfg.Keys))
	for _, k := range cfg.Keys {
		pub, err := dsse.ParseEd25519PublicKey(k.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("trust root key %s: %w", k.KeyID, err)
		}
		if l := len(pub); l != ed25519PubSize {
			return nil, fmt.Errorf("trust root key %s: expected %d-byte ed25519 key, got %d", k.KeyID, ed25519PubSize, l)
		}
		computed := dsse.KeyIDFromPublic(pub)
		if k.KeyID != "" && k.KeyID != computed {
			return nil, fmt.Errorf("trust root key %s: keyId does not match key (computed %s)", k.KeyID, computed)
		}
		pk := dsse.PublicKey{KeyID: computed, BuilderID: k.BuilderID, Raw: pub}
		ring[computed] = pk
		byBuilder[k.BuilderID] = pk
	}
	root := &Root{Config: cfg, Ring: ring, ByBuilder: byBuilder}
	if root.Config.Version == 0 {
		root.Config.Version = 1
	}
	return root, nil
}

const ed25519PubSize = 32
