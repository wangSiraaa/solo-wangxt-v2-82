package verify_test

import (
	"context"
	"testing"

	"github.com/example/verifybench/internal/demo"
	"github.com/example/verifybench/internal/policy"
	"github.com/example/verifybench/internal/trust"
	"github.com/example/verifybench/internal/verify"
)

func newVerifier(t *testing.T) *verify.Verifier {
	t.Helper()
	root, err := trust.Load(demo.TrustRoot())
	if err != nil {
		t.Fatalf("load trust root: %v", err)
	}
	eval, err := policy.New()
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return verify.New(root, eval)
}

func runScenario(t *testing.T, id string) *verify.Record {
	t.Helper()
	sc, err := demo.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := demo.Artifact(id)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := demo.Envelope(id)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := newVerifier(t).Verify(context.Background(), sc.ArtifactFile, artifact, envelope)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return rec
}

func TestNormalScenarioAllowed(t *testing.T) {
	rec := runScenario(t, "normal")
	if rec.Fatal != nil {
		t.Fatalf("unexpected fatal: %+v", rec.Fatal)
	}
	if !rec.Allow {
		t.Fatalf("expected allow, got violations %+v", rec.Violations)
	}
	if !rec.Checks["signatureValid"] || !rec.Checks["issuerTrusted"] ||
		!rec.Checks["digestMatch"] || !rec.Checks["policyAllow"] {
		t.Fatalf("expected all headline checks true, got %+v", rec.Checks)
	}
	if rec.ArtifactSHA256 != rec.SubjectDigest {
		t.Fatal("artifact digest must equal subject digest")
	}
}

func TestTamperedScenarioRejectedOnDigest(t *testing.T) {
	rec := runScenario(t, "tampered")
	if rec.Allow {
		t.Fatal("tampered artifact must be denied")
	}
	if rec.Checks["signatureValid"] != true {
		t.Fatal("signature stays valid: only artifact bytes changed")
	}
	if rec.Checks["issuerTrusted"] != true {
		t.Fatal("issuer must stay trusted for tampered scenario")
	}
	if rec.Checks["digestMatch"] != false {
		t.Fatal("digestMatch must be false")
	}
	var found bool
	for _, v := range rec.Violations {
		if v.Code == "digest_mismatch" && v.Field == "subject[0].digest.sha256" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected digest_mismatch on subject[0].digest.sha256, got %+v", rec.Violations)
	}
	if rec.ArtifactSHA256 == rec.SubjectDigest {
		t.Fatal("tampered digest must differ from attested digest")
	}
}

func TestUntrustedBuilderRejectedOnIssuer(t *testing.T) {
	rec := runScenario(t, "untrusted")
	if rec.Allow {
		t.Fatal("untrusted builder must be denied")
	}
	if rec.Checks["digestMatch"] != true {
		t.Fatal("digest is consistent; failure must be trust, not content")
	}
	if rec.Checks["issuerTrusted"] != false || rec.Checks["signatureValid"] != false {
		t.Fatalf("issuer/signature must be untrusted, got %+v", rec.Checks)
	}
	codes := map[string]bool{}
	for _, v := range rec.Violations {
		codes[v.Code] = true
		if v.Code == "builder_untrusted" &&
			v.Field != "predicate.runDetails.builder.id" {
			t.Fatalf("builder_untrusted must point at builder.id, got field %q", v.Field)
		}
	}
	if !codes["builder_untrusted"] || !codes["signature_not_trusted"] {
		t.Fatalf("expected builder_untrusted + signature_not_trusted, got %+v", rec.Violations)
	}
}
