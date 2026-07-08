interface PublicValueProps {
  value: string;
  label?: string;
  /** an on-chain address / amount that is deliberately EXPOSED. */
  tone?: "address" | "amount" | "plain";
}

/** A piece of PUBLIC, on-chain-visible data: plain, legible, slightly warm. */
export function PublicValue({ value, label, tone = "plain" }: PublicValueProps) {
  return (
    <span className="public-row">
      {label ? <span className="public-tag">{label}</span> : null}
      <span className={`public-value tone-${tone}`}>{value}</span>
    </span>
  );
}
