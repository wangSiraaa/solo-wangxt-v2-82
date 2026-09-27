import { useState } from "react";

/** JsonView 以等宽折叠块展示证据 JSON。 */
export default function JsonView({ data, label }: { data: unknown; label: string }) {
  const [open, setOpen] = useState(false);
  if (data === undefined || data === null) return null;
  return (
    <div className="json-view">
      <button className="json-toggle" onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"} {label}
      </button>
      {open && <pre>{JSON.stringify(data, null, 2)}</pre>}
    </div>
  );
}
