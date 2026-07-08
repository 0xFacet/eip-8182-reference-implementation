import { useState } from "react";

export function CopyButton({ value, label = "copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="copy-btn"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1100);
        } catch {
          /* clipboard unavailable */
        }
      }}
    >
      {done ? "copied" : label}
    </button>
  );
}
