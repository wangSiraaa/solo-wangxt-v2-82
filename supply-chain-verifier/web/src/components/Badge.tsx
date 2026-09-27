export function DecisionBadge({ decision }: { decision: "allow" | "deny" }) {
  return (
    <span className={`badge ${decision === "allow" ? "badge-ok" : "badge-bad"}`}>
      {decision === "allow" ? "✓ 允许" : "✗ 拒绝"}
    </span>
  );
}

export function StatusIcon({ ok }: { ok: boolean }) {
  return <span className={ok ? "status-ok" : "status-bad"}>{ok ? "✓" : "✗"}</span>;
}
