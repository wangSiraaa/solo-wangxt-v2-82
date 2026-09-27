import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, Demo } from "../api";

/** 上传核验页:本地产物 + DSSE 证据上传,以及三组固定演示数据。 */
export default function UploadPage() {
  const nav = useNavigate();
  const [artifact, setArtifact] = useState<File | null>(null);
  const [envelope, setEnvelope] = useState<File | null>(null);
  const [demos, setDemos] = useState<Demo[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.demos().then(setDemos).catch((e) => setError(String(e.message ?? e)));
  }, []);

  const submit = async () => {
    if (!artifact || !envelope) return;
    setBusy("upload");
    setError(null);
    try {
      const res = await api.verifyUpload(artifact, envelope);
      nav(`/verifications/${res.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const runDemo = async (name: string) => {
    setBusy(name);
    setError(null);
    try {
      const res = await api.verifyDemo(name);
      nav(`/verifications/${res.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="page">
      <section className="card">
        <h2>上传本地产物与 DSSE 证据</h2>
        <p className="hint">
          产物文件只用于计算 SHA-256 摘要并与 in-toto 声明比对;DSSE
          证据用于验签与策略判定。核验失败时产物不会被执行。
        </p>
        <div className="form-row">
          <label>
            <span>本地产物文件</span>
            <input
              type="file"
              onChange={(e) => setArtifact(e.target.files?.[0] ?? null)}
            />
          </label>
          <label>
            <span>DSSE 证据(envelope.json)</span>
            <input
              type="file"
              accept=".json,application/json"
              onChange={(e) => setEnvelope(e.target.files?.[0] ?? null)}
            />
          </label>
        </div>
        <button
          className="primary"
          disabled={!artifact || !envelope || busy !== null}
          onClick={submit}
        >
          {busy === "upload" ? "核验中…" : "开始核验"}
        </button>
        {error && <div className="error-box">{error}</div>}
      </section>

      <section className="card">
        <h2>固定演示数据</h2>
        <p className="hint">三组内置用例,便于逐项录制核验结果:</p>
        <div className="demo-grid">
          {demos.map((d) => (
            <div key={d.name} className="demo-card">
              <div className="demo-head">
                <code>{d.name}</code>
                <span
                  className={`badge ${d.expect === "allow" ? "badge-ok" : "badge-bad"}`}
                >
                  预期 {d.expect === "allow" ? "允许" : "拒绝"}
                </span>
              </div>
              <p>{d.desc}</p>
              <button
                disabled={busy !== null}
                onClick={() => runDemo(d.name)}
              >
                {busy === d.name ? "核验中…" : "运行核验"}
              </button>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
