import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Summary } from "../api";
import { DecisionBadge } from "../components/Badge";

/** 历史记录页:列出全部核验判定。 */
export default function HistoryPage() {
  const [items, setItems] = useState<Summary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.list().then(setItems).catch((e) => setError(String(e.message ?? e)));
  }, []);

  return (
    <div className="page">
      <section className="card">
        <h2>核验历史</h2>
        {error && <div className="error-box">{error}</div>}
        {items.length === 0 && !error && <p className="hint">暂无记录。</p>}
        {items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>时间</th>
                <th>来源</th>
                <th>产物</th>
                <th>SHA-256</th>
                <th>判定</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.id}>
                  <td>{new Date(it.createdAt).toLocaleString()}</td>
                  <td>
                    <code>{it.source}</code>
                  </td>
                  <td>{it.artifactName}</td>
                  <td>
                    <code className="mono-sm">{it.artifactSha256.slice(0, 16)}…</code>
                  </td>
                  <td>
                    <DecisionBadge decision={it.decision} />
                  </td>
                  <td>
                    <Link to={`/verifications/${it.id}`}>判定详情 →</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
