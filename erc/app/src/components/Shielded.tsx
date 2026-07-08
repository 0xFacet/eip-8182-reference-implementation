import { useState } from "react";

interface ShieldedProps {
  /** the sensitive value (hex / field / ciphertext). */
  value: string;
  /** short label shown to the left. */
  label?: string;
  /** already-shortened display string; falls back to value. */
  display?: string;
  title?: string;
}

/**
 * A piece of PRIVATE cryptographic material: monospace, blurred + softly glowing
 * by default, sharpening to fully legible on hover / focus / click. This is the
 * core "shielded" half of the public-vs-private visual language.
 */
export function Shielded({ value, label, display, title }: ShieldedProps) {
  const [pinned, setPinned] = useState(false);
  const shown = display ?? value;
  return (
    <span className={`shielded-row${pinned ? " is-pinned" : ""}`}>
      {label ? <span className="shielded-tag">{label}</span> : null}
      <span
        className="shielded"
        tabIndex={0}
        role="button"
        aria-label={title ?? label ?? "shielded value — reveal"}
        title={title ?? "click to reveal / pin"}
        onClick={() => setPinned((p) => !p)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setPinned((p) => !p);
          }
        }}
      >
        <span className="shielded-text">{shown}</span>
      </span>
    </span>
  );
}
