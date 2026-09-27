import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'

function FileDrop({
  label,
  hint,
  file,
  onPick,
}: {
  label: string
  hint: string
  file: File | null
  onPick: (f: File) => void
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  return (
    <div
      className={`dropzone ${file ? 'filled' : ''}`}
      onClick={() => inputRef.current?.click()}
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault()
        const f = e.dataTransfer.files?.[0]
        if (f) onPick(f)
      }}
    >
      <input
        ref={inputRef}
        type="file"
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) onPick(f)
          e.target.value = ''
        }}
      />
      <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: 4 }}>{label}</div>
      {file ? (
        <div className="fname">
          {file.name}（{file.size} 字节）
        </div>
      ) : (
        <div>{hint}</div>
      )}
    </div>
  )
}

export default function VerifyPage() {
  const [artifact, setArtifact] = useState<File | null>(null)
  const [envelope, setEnvelope] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  async function submit() {
    if (!artifact || !envelope) return
    setBusy(true)
    setError(null)
    try {
      const rec = await api.verifyUpload(artifact, envelope)
      navigate(`/verifications/${rec.id}`)
    } catch (e) {
      setError(String(e))
      setBusy(false)
    }
  }

  return (
    <div>
      <h1>上传核验</h1>
      <p className="subtitle">
        上传本地产物与对应的 DSSE 证据（.json）。后端仅对产物做哈希计算与证据比对，
        不执行产物内容；核验结果自动入库并跳转判定详情。
      </p>

      <div className="grid cols-2">
        <div className="card">
          <h2>① 构建产物</h2>
          <FileDrop
            label="选择产物文件"
            hint="点击或拖拽上传。文件名用于匹配 in-toto subject[].name"
            file={artifact}
            onPick={setArtifact}
          />
        </div>
        <div className="card">
          <h2>② DSSE 证据（in-toto 声明）</h2>
          <FileDrop
            label="选择 DSSE 封装 JSON"
            hint="包含 payloadType / payload / signatures 的 .json 文件"
            file={envelope}
            onPick={setEnvelope}
          />
        </div>
      </div>

      {error && <div className="error-box">{error}</div>}

      <div className="mt16 row">
        <button
          className="btn primary"
          disabled={!artifact || !envelope || busy}
          onClick={submit}
        >
          {busy ? '核验中…' : '开始核验'}
        </button>
        <span className="small muted">
          提示：可在<em>首页</em>下载演示产物与证据后，在这里逐项复现核验。
        </span>
      </div>
    </div>
  )
}
