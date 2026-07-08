import type { ReactNode } from "react";

interface CardProps {
  title?: ReactNode;
  eyebrow?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  accent?: boolean;
}

export function Card({ title, eyebrow, right, children, className, accent }: CardProps) {
  return (
    <section className={`card${accent ? " card-accent" : ""}${className ? ` ${className}` : ""}`}>
      {(title || right || eyebrow) && (
        <header className="card-head">
          <div>
            {eyebrow ? <div className="eyebrow">{eyebrow}</div> : null}
            {title ? <h3 className="card-title">{title}</h3> : null}
          </div>
          {right ? <div className="card-right">{right}</div> : null}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}
