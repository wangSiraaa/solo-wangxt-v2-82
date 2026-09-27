// Package api implements the HTTP JSON API and static frontend serving.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/example/verifybench/internal/demo"
	"github.com/example/verifybench/internal/policy"
	"github.com/example/verifybench/internal/store"
	"github.com/example/verifybench/internal/trust"
	"github.com/example/verifybench/internal/verify"
)

// Server wires the verifier, store and demo data to HTTP handlers.
type Server struct {
	verifier *verify.Verifier
	store    store.Store
	root     *trust.Root
	mux      *http.ServeMux
}

// NewServer constructs the API router.
func NewServer(v *verify.Verifier, st store.Store, root *trust.Root) *Server {
	s := &Server{verifier: v, store: st, root: root, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.health)
	s.mux.HandleFunc("GET /api/policy", s.getPolicy)
	s.mux.HandleFunc("GET /api/trust-root", s.getTrustRoot)
	s.mux.HandleFunc("GET /api/demo", s.listDemo)
	s.mux.HandleFunc("GET /api/demo/{id}/artifact", s.demoArtifact)
	s.mux.HandleFunc("GET /api/demo/{id}/envelope", s.demoEnvelope)
	s.mux.HandleFunc("POST /api/verify", s.verifyUpload)
	s.mux.HandleFunc("POST /api/verify/demo/{id}", s.verifyDemo)
	s.mux.HandleFunc("GET /api/verifications", s.listVerifications)
	s.mux.HandleFunc("GET /api/verifications/{id}", s.getVerification)
	s.mux.HandleFunc("GET /api/verifications/{id}/artifact", s.getArtifact)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"store":  s.store.Kind(),
	})
}

func (s *Server) getPolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"rego": policy.PolicySource()})
}

func (s *Server) getTrustRoot(w http.ResponseWriter, _ *http.Request) {
	type keyOut struct {
		KeyID     string `json:"keyId"`
		BuilderID string `json:"builderId"`
	}
	keys := make([]keyOut, 0, len(s.root.Ring))
	for _, k := range s.root.Ring {
		keys = append(keys, keyOut{KeyID: k.KeyID, BuilderID: k.BuilderID})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].BuilderID < keys[j].BuilderID })
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":            s.root.Config.Version,
		"keys":               keys,
		"allowedSourceHosts": s.root.Config.AllowedSourceHosts,
		"allowedBuildTypes":  s.root.Config.AllowedBuildTypes,
	})
}

func (s *Server) listDemo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"scenarios": demo.Scenarios()})
}

func (s *Server) demoArtifact(w http.ResponseWriter, r *http.Request) {
	sc, err := demo.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	data, err := demo.Artifact(sc.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename=%q`, sc.ArtifactFile))
	_, _ = w.Write(data)
}

func (s *Server) demoEnvelope(w http.ResponseWriter, r *http.Request) {
	data, err := demo.Envelope(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

const maxUpload = 64 << 20 // 64 MiB per part

// verifyUpload accepts multipart form fields "artifact" (the build product
// bytes) and "envelope" (DSSE JSON). The artifact is only hashed, never
// executed or interpreted.
func (s *Server) verifyUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		writeError(w, http.StatusBadRequest, "parse multipart form: "+err.Error())
		return
	}
	artifactFile, artifactName, err := readFilePart(r, "artifact")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	envelopeFile, _, err := readFilePart(r, "envelope")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := s.verifier.Verify(r.Context(), artifactName, artifactFile, envelopeFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.finishVerify(w, r, rec, artifactFile)
}

// verifyDemo runs the same pipeline against an embedded fixed scenario.
func (s *Server) verifyDemo(w http.ResponseWriter, r *http.Request) {
	sc, err := demo.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	artifact, err := demo.Artifact(sc.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	envelope, err := demo.Envelope(sc.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	rec, err := s.verifier.Verify(r.Context(), sc.ArtifactFile, artifact, envelope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.finishVerify(w, r, rec, artifact)
}

// finishVerify persists the record. Artifact bytes are retained ONLY when the
// policy allows, so denied content can never later be downloaded/executed.
func (s *Server) finishVerify(w http.ResponseWriter, r *http.Request, rec *verify.Record, artifact []byte) {
	if err := s.store.Save(r.Context(), rec); err != nil {
		writeError(w, http.StatusInternalServerError, "save record: "+err.Error())
		return
	}
	if rec.Allow {
		if err := s.store.SaveArtifact(r.Context(), rec.ID, artifact); err != nil {
			log.Printf("store allowed artifact: %v", err)
		}
	}
	writeJSON(w, http.StatusCreated, rec)
}

func (s *Server) listVerifications(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, total, err := s.store.List(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []*verify.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": total})
}

func (s *Server) getVerification(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "record not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// getArtifact returns artifact bytes only for records the policy allowed.
// Denied records have no stored bytes and receive 403 — there is no path by
// which a failed verification yields executable/downloadable content.
func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "record not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !rec.Allow {
		writeError(w, http.StatusForbidden,
			"artifact content is withheld: verification policy denied this record ("+firstReason(rec)+")")
		return
	}
	data, err := s.store.LoadArtifact(r.Context(), rec.ID)
	if err != nil {
		if errors.Is(err, store.ErrArtifactUnavailable) {
			writeError(w, http.StatusNotFound, "artifact bytes are not retained for this record")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename=%q`, rec.ArtifactName))
	_, _ = w.Write(data)
}

func firstReason(rec *verify.Record) string {
	if rec.Fatal != nil {
		return rec.Fatal.Code
	}
	if len(rec.Violations) > 0 {
		return rec.Violations[0].Code
	}
	return "policy denied"
}

func readFilePart(r *http.Request, field string) ([]byte, string, error) {
	f, header, err := r.FormFile(field)
	if err != nil {
		return nil, "", fmt.Errorf("missing file part %q: %w", field, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUpload))
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", field, err)
	}
	name := strings.TrimSpace(header.Filename)
	if name == "" {
		return nil, "", fmt.Errorf("%s has empty filename", field)
	}
	return data, name, nil
}
