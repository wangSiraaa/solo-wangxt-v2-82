import { useEffect, useState } from 'react'
import { api } from '../api'
import type { TrustRoot } from '../types'

export default function PolicyPage() {
  const [rego, setRego] = useState<string>('')
  const [root, setRoot] = useState<TrustRoot | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.policy().then(setRego).catch((e) => setError(String(e)))
    api.trustRoot().then(setRoot).catch(() => setRoot(null))
  }, [])

  return (
    <div>
      <h1>信任策略与信任根</h1>
      <p className="subtitle">
        判定完全由以下显式策略决定：OPA Rego 规则 + 信任根（受信构建者密钥、允许的源码宿主与构建类型）。
      </p>
      {error && <div className="error-box">{error}</div>}

      {root && (
        <>
          <div className="section-title">信任根（v{root.version}）</div>
          <div className="grid cols-2">
            <div className="card">
              <h2>受信构建者密钥</h2>
              {root.keys.map((k) => (
                <div className="check-row" key={k.keyId}>
                  <span className="dot ok" />
                  <div className="grow">
                    <div className="mono small">{k.builderId}</div>
                    <div className="mono small muted">{k.keyId}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className="card">
              <h2>允许列表</h2>
              <dl className="kv">
                <dt>源码宿主</dt>
                <dd>{root.allowedSourceHosts.map((h) => <div key={h} className="mono small">{h}</div>)}</dd>
                <dt>构建类型</dt>
                <dd>{root.allowedBuildTypes.map((t) => <div key={t} className="mono small">{t}</div>)}</dd>
              </dl>
            </div>
          </div>
        </>
      )}

      <div className="section-title">OPA Rego 策略</div>
      <div className="card" style={{ padding: 12 }}>
        <pre className="codeblock">{rego || '加载中…'}</pre>
      </div>
    </div>
  )
}
