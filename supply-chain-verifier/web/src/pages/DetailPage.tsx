import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, Record, VerifyResult } from "../api";
import { DecisionBadge, StatusIcon } from "../components/Badge";
import JsonView from "../components/JsonView";

/** 判定详情页:四个面板分别展示签名有效性、签发者信任、摘要一致性、策略结论。 */
export default function DetailPage() {
  const { id } = useParams<{ id: string }>();
  const [rec, setRec] = useState<Record | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    api.get(id).then(setRec).catch((e) => setError(String(e.message ?? e)));
  }, [id]);

  if (error) return <div className="page"><div className="error-box">{error}</div></div>;
  if (!rec) return <div className="page"><p className="hint">加载中…</p></div>;

  const r: VerifyResult = rec.result;

  return (
    <div className="page">
      <section className="card detail-head">
        <div>
          <h2>
            判定详情 <DecisionBadge decision={rec.decision} />
          </h2>
          <dl className="meta">
            <div><dt>产物</dt><dd>{rec.artifactName}</dd></div>
            <div><dt>SHA-256</dt><dd><code className="mono-sm">{rec.artifactSha256}</code></dd></div>
            <div><dt>来源</dt><dd><code>{rec.source}</code></dd></div>
            <div><dt>时间</dt><dd>{new Date(rec.createdAt).toLocaleString()}</dd></div>
          </dl>
        </div>
        <Link to="/history" className="back-link">← 返回历史</Link>
      </section>

      <div className="panel-grid">
        {/* 面板一:签名有效性 */}
        <section className={`panel ${r.signature.ok ? "panel-ok" : "panel-bad"}`}>
          <h3><StatusIcon ok={r.signature.ok} /> 签名有效性</h3>
          {r.signature.error && <p className="fail-reason">{r.signature.error}</p>}
          {r.signature.payloadType && (
            <p>载荷类型:<code>{r.signature.payloadType}</code></p>
          )}
          {r.signature.results.map((s) => (
            <div key={s.index} className="kv">
              <span>
                签名[{s.index}] keyid=<code>{s.keyid || "(空)"}</code>
              </span>
              <StatusIcon ok={s.valid} />
            </div>
          ))}
          {r.signature.results.filter((s) => !s.valid).map((s) => (
            <div key={`f${s.index}`} className="field-loc">
              失败字段:<code>{s.field}</code>
              <br />原因:{s.reason}
            </div>
          ))}
        </section>

        {/* 面板二:签发者信任 */}
        <section className={`panel ${r.issuer.ok ? "panel-ok" : "panel-bad"}`}>
          <h3><StatusIcon ok={r.issuer.ok} /> 签发者信任</h3>
          <div className="kv"><span>keyid</span><code>{r.issuer.keyid || "(空)"}</code></div>
          {r.issuer.owner && <div className="kv"><span>密钥属主</span><span>{r.issuer.owner}</span></div>}
          <div className="kv">
            <span>信任状态</span>
            <span>{r.issuer.ok ? "受信签名者" : "不受信任"}</span>
          </div>
          {!r.issuer.ok && (
            <div className="field-loc">
              失败字段:<code>{r.issuer.field}</code>
              {r.issuer.message && <><br />原因:{r.issuer.message}</>}
            </div>
          )}
        </section>

        {/* 面板三:摘要一致性 */}
        <section className={`panel ${r.digest.ok ? "panel-ok" : "panel-bad"}`}>
          <h3><StatusIcon ok={r.digest.ok} /> 摘要一致性</h3>
          <div className="digest-row">
            <span>声明中的摘要</span>
            <code className="mono-sm">{r.digest.expected || "(缺失)"}</code>
          </div>
          <div className="digest-row">
            <span>本地产物实际摘要</span>
            <code className="mono-sm">{r.digest.actual}</code>
          </div>
          {!r.digest.ok && (
            <div className="field-loc">
              失败字段:<code>{r.digest.field}</code>
              {r.digest.message && <><br />原因:{r.digest.message}</>}
            </div>
          )}
        </section>

        {/* 面板四:策略结论 */}
        <section className={`panel ${r.policy.allow ? "panel-ok" : "panel-bad"}`}>
          <h3><StatusIcon ok={r.policy.allow} /> 策略结论(OPA)</h3>
          <p>
            {r.policy.allow
              ? "全部信任策略通过,允许使用该产物。"
              : `未通过 ${r.policy.violations.length} 项策略检查,已拒绝。产物内容未被执行。`}
          </p>
          {r.policy.violations.length > 0 && (
            <ul className="violation-list">
              {r.policy.violations.map((v, i) => (
                <li key={i}>
                  <code>{v.field}</code>
                  <span>{v.message}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="card">
        <h2>证据原文</h2>
        <JsonView data={rec.envelope} label="DSSE 信封(envelope)" />
        <JsonView data={rec.statement} label="in-toto 声明(statement)" />
      </section>
    </div>
  );
}
