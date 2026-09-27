import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import type { VerificationRecord } from '../types'
import ChecksPanel from '../components/ChecksPanel'
import ViolationsList from '../components/ViolationsList'
import VerdictBanner from '../components/VerdictBanner'

/** 按 "subject[0].digest.sha256" 形式的路径取值。 */
function resolvePath(obj: unknown, path: string): unknown {
  const parts = path
    .replace(/\[(\d+)\]/g, '.$1')
    .split('.')
    .filter(Boolean)
  let cur: unknown = obj
  for (const p of parts) {
    if (cur === null || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[p]
  }
  return cur
}

/** 在 pretty JSON 中高亮包含违规叶子键的行。 */
function HighlightedJSON({ data, fields }: { data: unknown; fields: string[] }) {
  const text = useMemo(() => JSON.stringify(data, null, 2), [data])
  const leafKeys = useMemo(
    () =>
      new Set(
        fields
          .map((f) => f.replace(/\[\d+\]/g, '').split('.').filter(Boolean).pop())
          .filter((k): k is string => Boolean(k)),
      ),
    [fields],
  )
  const lines = text.split('\n')
  return (
    <pre className="codeblock">
      {lines.map((line, i) => {
        const m = line.match(/"([^"]+)"\s*:/)
        const hot = m && leafKeys.has(m[1])
        return (
          <div
            key={i}
            style={
              hot
                ? { background: 'rgba(248,113,113,.16)', margin: '0 -16px', padding: '0 16px' }
                : undefined
            }
          >
            {line}
          </div>
        )
      })}
    </pre>
  )
}

export default function DetailPage() {
  const { id } = useParams<{ id: string }>()
  const [rec, setRec] = useState<VerificationRecord | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    api.get(id).then(setRec).catch((e) => setError(String(e)))
  }, [id])

  if (error) return <div className="error-box">{error}</div>
  if (!rec) return <div className="empty">加载中…</div>

  const violationFields = (rec.violations ?? []).map((v) => v.field)
  const envelopeParsed =
    typeof rec.envelopeRaw === 'object' && rec.envelopeRaw !== null
      ? (rec.envelopeRaw as Record<string, unknown>)
      : null
  const envelopeObj = rec.envelopeRaw ?? null

  // signature_* 违规的字段位于 DSSE 封装层（signatures[]），其余位于声明层。
  const statementFields = violationFields.filter((f) => !f.startsWith('signatures'))
  const envelopeFields = violationFields.filter((f) => f.startsWith('signatures'))
  const resolveFor = (field: string): unknown =>
    field.startsWith('signatures') && envelopeParsed
      ? resolvePath(envelopeParsed, field)
      : resolvePath(rec.statement, field)

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h1>判定详情</h1>
        <Link to="/history" className="small">← 返回历史记录</Link>
      </div>
      <p className="subtitle mono">{rec.id}</p>

      <VerdictBanner allow={rec.allow} fatal={Boolean(rec.fatal)} />

      <div className="grid cols-2 mt16">
        <div className="card">
          <h2>产物信息</h2>
          <dl className="kv">
            <dt>文件名</dt><dd className="mono">{rec.artifactName}</dd>
            <dt>大小</dt><dd>{rec.artifactSize} 字节</dd>
            <dt>实测 sha256</dt><dd className="mono">{rec.artifactSha256}</dd>
            <dt>声明 sha256</dt>
            <dd className="mono">{rec.subjectDigest || '（subject 未匹配）'}</dd>
            <dt>核验时间</dt>
            <dd className="mono">{new Date(rec.createdAt).toISOString()}</dd>
          </dl>
          <div className="mt16">
            {rec.allow ? (
              <a className="btn primary" href={api.artifactURL(rec.id)} download>
                下载产物
              </a>
            ) : (
              <>
                <button className="btn" disabled title="策略拒绝的记录不保留产物字节">
                  下载产物（已禁用）
                </button>
                <div className="small muted mt8">
                  核验未通过：产物内容未被保留，无法下载或执行。
                </div>
              </>
            )}
          </div>
        </div>

        <div className="card">
          <h2>签发与构建</h2>
          <dl className="kv">
            <dt>builder.id</dt><dd className="mono">{rec.builderId || '—'}</dd>
            <dt>buildType</dt><dd className="mono">{rec.buildType || '—'}</dd>
            <dt>源码 URI</dt><dd className="mono">{rec.sourceUri || '—'}</dd>
            <dt>源码提交</dt><dd className="mono">{rec.sourceCommit || '—'}</dd>
            <dt>payloadType</dt><dd className="mono">{rec.payloadType || '—'}</dd>
          </dl>
        </div>
      </div>

      <div className="section-title">核验项</div>
      <div className="card">
        <ChecksPanel record={rec} extended />
      </div>

      <div className="section-title">签名明细</div>
      <div className="card">
        {!rec.signatures || rec.signatures.length === 0 ? (
          <div className="muted small">无签名信息（证据可能无法解析）。</div>
        ) : (
          rec.signatures.map((s, i) => (
            <div className="check-row" key={i}>
              <span className={`dot ${s.valid && s.trusted ? 'ok' : 'bad'}`} />
              <div className="grow">
                <div className="mono small">keyid: {s.keyId}</div>
                <div className="check-desc">{s.detail}</div>
              </div>
              <span className={`badge ${s.valid && s.trusted ? 'ok' : 'bad'}`}>
                {s.valid && s.trusted ? '有效且可信' : s.trusted ? '签名无效' : '密钥不受信任'}
              </span>
            </div>
          ))
        )}
      </div>

      {!rec.allow && (
        <>
          <div className="section-title">失败原因（定位到证据字段）</div>
          <div className="card">
            <ViolationsList record={rec} />
            {violationFields.length > 0 && (
              <table className="mt16">
                <thead>
                  <tr><th>证据字段</th><th>字段当前值</th></tr>
                </thead>
                <tbody>
                  {violationFields.map((f) => {
                    const val = resolveFor(f)
                    return (
                      <tr key={f}>
                        <td><span className="field-path">{f}</span></td>
                        <td className="mono small">
                          {val === undefined ? '（字段缺失）' : JSON.stringify(val)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      <div className="section-title">in-toto 声明（证据原文，失败字段已高亮）</div>
      <div className="card" style={{ padding: 12 }}>
        {rec.statement ? (
          <HighlightedJSON data={rec.statement} fields={statementFields} />
        ) : (
          <div className="muted small" style={{ padding: 8 }}>声明未能解析，无内容。</div>
        )}
      </div>

      <div className="section-title">DSSE 封装原文（签名失败字段已高亮）</div>
      <div className="card" style={{ padding: 12 }}>
        {envelopeParsed ? (
          <HighlightedJSON data={envelopeParsed} fields={envelopeFields} />
        ) : (
          <pre className="codeblock">{typeof envelopeObj === 'string'
            ? envelopeObj
            : JSON.stringify(envelopeObj, null, 2)}</pre>
        )}
      </div>
    </div>
  )
}
