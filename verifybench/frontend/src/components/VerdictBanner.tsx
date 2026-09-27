export default function VerdictBanner({ allow, fatal }: { allow: boolean; fatal?: boolean }) {
  if (allow) {
    return (
      <div className="verdict allow">
        <span style={{ fontSize: 22 }}>✓</span>
        核验通过 —— 产物来源与构建流程均符合信任策略，允许下载
      </div>
    )
  }
  return (
    <div className="verdict deny">
      <span style={{ fontSize: 22 }}>✗</span>
      {fatal ? '证据无法解析 —— 核验中止，产物不可用' : '核验未通过 —— 产物内容已被隔离，禁止下载与执行'}
    </div>
  )
}
