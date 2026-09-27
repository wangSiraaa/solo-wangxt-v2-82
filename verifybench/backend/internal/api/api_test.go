package api_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/example/verifybench/internal/api"
	"github.com/example/verifybench/internal/demo"
	"github.com/example/verifybench/internal/policy"
	"github.com/example/verifybench/internal/store"
	"github.com/example/verifybench/internal/trust"
	"github.com/example/verifybench/internal/verify"
)

func newServer(t *testing.T) http.Handler {
	t.Helper()
	root, err := trust.Load(demo.TrustRoot())
	if err != nil {
		t.Fatal(err)
	}
	eval, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}
	return api.NewServer(verify.New(root, eval), store.NewMem(), root).Handler()
}

func verifyDemo(t *testing.T, h http.Handler, id string) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/verify/demo/"+id, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDeniedArtifactIsWithheld(t *testing.T) {
	h := newServer(t)
	denied := verifyDemo(t, h, "tampered")
	id, _ := denied["id"].(string)

	req := httptest.NewRequest(http.MethodGet, "/api/verifications/"+id+"/artifact", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied artifact must return 403, got %d", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("INJECTED")) {
		t.Fatal("denied artifact content leaked in the 403 response")
	}
}

func TestAllowedArtifactIsDownloadable(t *testing.T) {
	h := newServer(t)
	allowed := verifyDemo(t, h, "normal")
	id, _ := allowed["id"].(string)

	req := httptest.NewRequest(http.MethodGet, "/api/verifications/"+id+"/artifact", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed artifact must return 200, got %d: %s", rec.Code, rec.Body.String())
	}
	want, _ := demo.Artifact("normal")
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatal("downloaded bytes differ from the verified artifact")
	}
}

func TestUploadAndMalformedEvidence(t *testing.T) {
	h := newServer(t)

	// Multipart upload of the tampered artifact against the normal envelope.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	artifact, _ := demo.Artifact("tampered")
	envelope, _ := demo.Envelope("normal")
	w1, _ := mw.CreateFormFile("artifact", "hello-release.txt")
	_, _ = w1.Write(artifact)
	w2, _ := mw.CreateFormFile("envelope", "envelope.json")
	_, _ = w2.Write(envelope)
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/verify", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["allow"] != false {
		t.Fatal("uploaded tampered artifact must be denied")
	}

	// Malformed evidence must still produce a valid record carrying a fatal error.
	var bad bytes.Buffer
	mw2 := multipart.NewWriter(&bad)
	b1, _ := mw2.CreateFormFile("artifact", "x.txt")
	_, _ = b1.Write([]byte("x"))
	b2, _ := mw2.CreateFormFile("envelope", "bad.json")
	_, _ = b2.Write([]byte("not json"))
	_ = mw2.Close()

	req2 := httptest.NewRequest(http.MethodPost, "/api/verify", &bad)
	req2.Header.Set("Content-Type", mw2.FormDataContentType())
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("expected 201 for malformed evidence, got %d", rec2.Code)
	}
	var fatalRec map[string]interface{}
	_ = json.Unmarshal(rec2.Body.Bytes(), &fatalRec)
	fatal, ok := fatalRec["fatal"].(map[string]interface{})
	if !ok || fatal["code"] != "envelope_parse_error" {
		t.Fatalf("expected envelope_parse_error fatal, got %v", fatalRec["fatal"])
	}
}
