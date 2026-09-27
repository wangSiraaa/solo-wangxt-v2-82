import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { DemoScenario } from '../types'

export default function HomePage() {
  const [scenarios, setScenarios] = useState<DemoScenario[]>([])
  const [running, setRunning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    api.demos().then(setScenarios).catch((e) => setError(String(e)))
  }, [])

  async function run(id: string) {
    setRunning(id)
    setError(null)
    try {
      const rec = await api.verifyDemo(id)
      navigate(`/verifications/${rec.id}`)
    } catch (e) {
      setError(String(e))
      setRunning(null)
    }
  }

  return (
    <div>
      <h1>固定演示场景</h1>
      <p className="subtitle">
        三组内置数据覆盖完整核验路径：正常产物、签名后被篡改的产物、不受信任构建者签发的产物。
        点击「运行核验」即调用与上传相同的后端流水线（DSSE 解析 → Ed25519 验签 → in-toto 解析 → OPA 策略 → 入库）。
      </p>

      {error && <div className="error-box">{error}</div>}

      <div className="grid cols-3">
        {scenarios.map((s) => (
          <div className="card demo-card" key={s.id}>
            <div className="title">
              {s.title}
              {s.expectedAllow ? (
                <span className="badge ok">预期通过</span>
              ) : (
                <span className="badge bad">预期拒绝</span>
              )}
            </div>
            <p>{s.description}</p>
            <div className="small muted mono">产物文件：{s.artifactFile}</div>
            <div className="demo-links">
              <a href={api.demoArtifactURL(s.id)} download>下载产物样本</a>
              <a href={api.demoEnvelopeURL(s.id)} download>下载 DSSE 证据</a>
            </div>
            <button
              className="btn primary"
              disabled={running !== null}
              onClick={() => run(s.id)}
            >
              {running === s.id ? '核验中…' : '运行核验'}
            </button>
          </div>
        ))}
      </div>

      <div className="section-title">工作方式</div>
      <div className="grid cols-2">
        <div className="card">
          <h2>核验流水线</h2>
          <ol className="small muted" style={{ margin: 0, paddingLeft: 18 }}>
            <li>解析 DSSE 封装（payloadType / payload / signatures）</li>
            <li>按 DSSE PAE 编码重组签名内容，用 Ed25519 成熟密码库验签</li>
            <li>解析 in-toto 声明（SLSA provenance v1 谓词）</li>
            <li>计算产物 sha256（只哈希，绝不执行产物内容）</li>
            <li>OPA 执行显式信任策略，产出逐项检查与违规字段定位</li>
            <li>结果与证据写入 PostgreSQL；仅通过的记录保留产物字节</li>
          </ol>
        </div>
        <div className="card">
          <h2>安全边界</h2>
          <ul className="small muted" style={{ margin: 0, paddingLeft: 18 }}>
            <li>失败路径不执行产物内容：字节只被哈希，不进入任何执行环境</li>
            <li>策略拒绝的记录不保存产物字节，下载接口直接返回 403</li>
            <li>每条拒绝都定位到具体证据字段（如 subject[0].digest.sha256）</li>
            <li>信任根与策略可在 <Link to="/policy">信任策略页</Link> 查看</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
