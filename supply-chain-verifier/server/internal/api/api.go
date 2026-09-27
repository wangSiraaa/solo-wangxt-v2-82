// Package api 提供 HTTP 接口:上传核验、历史记录、判定详情、演示用例。
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/supply-chain-verifier/internal/store"
	"github.com/example/supply-chain-verifier/internal/verify"
)

// Server 持有路由依赖。
type Server struct {
	verifier *verify.Verifier
	st       *store.Store
	demoDir  string // fixtures 目录
	mux      *http.ServeMux
}

// New 构造 HTTP 服务。
func New(v *verify.Verifier, st *store.Store, demoDir string) *Server {
	s := &Server{verifier: v, st: st, demoDir: demoDir, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /api/health", s.health)
	s.mux.HandleFunc("POST /api/verify", s.verifyUpload)
	s.mux.HandleFunc("GET /api/verifications", s.list)
	s.mux.HandleFunc("GET /api/verifications/{id}", s.get)
	s.mux.HandleFunc("GET /api/demos", s.demos)
	s.mux.HandleFunc("POST /api/demos/{name}/verify", s.verifyDemo)
	return s
}

// Handler 返回带 CORS 的根 handler。
func (s *Server) Handler() http.Handler {
	return cors(s.mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// verifyUpload 接收 multipart 表单:artifact(本地产物)+ envelope(DSSE 证据)。
// 产物只用于计算摘要,绝不执行。
func (s *Server) verifyUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20) // 64MB 上限
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "解析 multipart 表单失败: "+err.Error())
		return
	}
	artifact, artifactName, err := readPart(r, "artifact", 32<<20)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取产物文件失败: "+err.Error())
		return
	}
	envelope, _, err := readPart(r, "envelope", 4<<20)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取 DSSE 证据文件失败: "+err.Error())
		return
	}
	s.runAndStore(w, r, "upload", artifactName, artifact, envelope)
}

// verifyDemo 用 fixtures 目录中的固定演示数据执行核验。
func (s *Server) verifyDemo(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.ContainsAny(name, `/\`) || name == "" {
		writeErr(w, http.StatusBadRequest, "非法用例名")
		return
	}
	dir := filepath.Join(s.demoDir, name)
	artifact, err := os.ReadFile(filepath.Join(dir, "artifact.bin"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "演示用例不存在: "+name)
		return
	}
	envelope, err := os.ReadFile(filepath.Join(dir, "envelope.json"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "演示用例证据缺失: "+name)
		return
	}
	s.runAndStore(w, r, "demo:"+name, "artifact.bin", artifact, envelope)
}

// runAndStore 执行核验、落库并返回结果。
func (s *Server) runAndStore(w http.ResponseWriter, r *http.Request, source, name string, artifact, envelope []byte) {
	res, err := s.verifier.Run(r.Context(), name, artifact, envelope)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resultJSON, _ := json.Marshal(res)
	rec := &store.Record{
		Source:         source,
		ArtifactName:   res.ArtifactName,
		ArtifactSHA256: res.ArtifactSHA256,
		Envelope:       res.Envelope,
		Statement:      res.Statement,
		Result:         resultJSON,
		Decision:       res.Decision,
	}
	id, err := s.st.Save(r.Context(), rec)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "保存核验记录失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "result": res})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	items, err := s.st.List(r.Context(), 50)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []store.Summary{}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	rec, err := s.st.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "记录不存在")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// demos 列出 fixtures 目录下的演示用例。
func (s *Server) demos(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.demoDir)
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	type demo struct {
		Name   string `json:"name"`
		Desc   string `json:"desc"`
		Expect string `json:"expect"`
	}
	out := []demo{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.demoDir, e.Name(), "case.json"))
		if err != nil {
			continue
		}
		var d demo
		if json.Unmarshal(b, &d) == nil {
			out = append(out, d)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func readPart(r *http.Request, name string, max int64) ([]byte, string, error) {
	f, h, err := r.FormFile(name)
	if err != nil {
		return nil, "", fmt.Errorf("缺少表单字段 %q", name)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(b)) > max {
		return nil, "", errors.New("文件超过大小限制")
	}
	return b, filepath.Base(h.Filename), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
