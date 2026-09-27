import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { VerificationRecord } from '../types'

export default function HistoryPage() {
  const [items, setItems] = useState<VerificationRecord[]>([])
  const [total, setTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .list(100)
      .then((r) => {
        setItems(r.items)
        setTotal(r.total)
      })
      .catch((e) => setError(String(e)))
  }, [])

  return (
    <div>
      <h1>历史记录</h1>
      <p className="subtitle">全部核验判定（共 {total} 条），按时间倒序。</p>
      {error && <div className="error-box">{error}</div>}
      {items.length === 0 && !error ? (
        <div className="card empty">暂无记录。先在首页运行演示，或上传产物与证据。</div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <table>
            <thead>
              <tr>
                <th>时间 (UTC)</th>
                <th>产物</th>
                <th>sha256</th>
                <th>构建者</th>
                <th>结论</th>
                <th>失败原因</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{new Date(r.createdAt).toISOString().replace('T', ' ').slice(0, 19)}</td>
                  <td className="mono">{r.artifactName}</td>
                  <td className="mono" title={r.artifactSha256}>
                    {r.artifactSha256.slice(0, 12)}…
                  </td>
                  <td className="mono small">{r.builderId || '—'}</td>
                  <td>
                    {r.allow ? (
                      <span className="badge ok">通过</span>
                    ) : (
                      <span className="badge bad">拒绝</span>
                    )}
                  </td>
                  <td className="small">
                    {r.fatal
                      ? r.fatal.code
                      : r.violations && r.violations.length > 0
                        ? r.violations.map((v) => v.code).join(', ')
                        : '—'}
                  </td>
                  <td>
                    <Link to={`/verifications/${r.id}`}>详情</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
