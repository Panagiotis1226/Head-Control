// Small hand-rolled UI kit (Tailwind). One place for visual consistency.

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

// ---- buttons ----

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

export function Button({
  variant = "secondary",
  className,
  disabled,
  loading,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  loading?: boolean;
}) {
  const styles: Record<ButtonVariant, string> = {
    primary:
      "bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-400 dark:disabled:bg-indigo-900",
    secondary:
      "bg-white text-slate-700 border border-slate-300 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-600 dark:hover:bg-slate-700",
    danger: "bg-red-600 text-white hover:bg-red-500 disabled:bg-red-400",
    ghost:
      "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800",
  };
  return (
    <button
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
        "focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 disabled:cursor-not-allowed disabled:opacity-60",
        styles[variant],
        className,
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
      )}
      {props.children}
    </button>
  );
}

// ---- form elements ----

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "w-full rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-900",
        "placeholder:text-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500",
        "dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100",
        props.className,
      )}
    />
  );
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={cn(
        "rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-900",
        "focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500",
        "dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100",
        props.className,
      )}
    />
  );
}

export function Checkbox({
  label,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-700 dark:text-slate-200">
      <input
        type="checkbox"
        {...props}
        className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 dark:border-slate-600"
      />
      {label}
    </label>
  );
}

export function Field({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{label}</span>
      {children}
      {hint && <span className="block text-xs text-slate-500 dark:text-slate-400">{hint}</span>}
    </label>
  );
}

// ---- badges / chips ----

type BadgeTone = "gray" | "green" | "yellow" | "red" | "blue" | "purple";

export function Badge({ tone = "gray", children, title }: { tone?: BadgeTone; children: ReactNode; title?: string }) {
  const tones: Record<BadgeTone, string> = {
    gray: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    green: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300",
    yellow: "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-300",
    red: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300",
    blue: "bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-300",
    purple: "bg-violet-100 text-violet-800 dark:bg-violet-900/50 dark:text-violet-300",
  };
  return (
    <span
      title={title}
      className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium", tones[tone])}
    >
      {children}
    </span>
  );
}

export function OnlineDot({ online }: { online: boolean }) {
  return (
    <span
      title={online ? "online" : "offline"}
      className={cn(
        "inline-block h-2 w-2 rounded-full",
        online ? "bg-emerald-500" : "bg-slate-300 dark:bg-slate-600",
      )}
    />
  );
}

// ---- cards / layout ----

export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section
      className={cn(
        "rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-900",
        className,
      )}
    >
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-700">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function EmptyState({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 px-6 py-10 text-center dark:border-slate-700">
      <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{title}</p>
      {children && <div className="mt-3 text-sm text-slate-500 dark:text-slate-400">{children}</div>}
    </div>
  );
}

// ---- modal ----

export function Modal({
  title,
  onClose,
  children,
  wide,
}: {
  title: ReactNode;
  onClose?: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose?.();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 pt-[8vh]">
      <div
        className={cn(
          "w-full rounded-lg bg-white shadow-xl dark:bg-slate-900",
          wide ? "max-w-3xl" : "max-w-md",
        )}
        role="dialog"
        aria-modal="true"
      >
        <header className="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-700">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          {onClose && (
            <button
              onClick={onClose}
              aria-label="Close"
              className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800"
            >
              ✕
            </button>
          )}
        </header>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

// ---- toasts ----

interface Toast {
  id: number;
  kind: "success" | "error";
  message: string;
  detail?: string;
}

const ToastCtx = createContext<{
  success: (message: string) => void;
  error: (message: string, detail?: string) => void;
}>({ success: () => {}, error: () => {} });

export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const push = (kind: Toast["kind"], message: string, detail?: string) => {
    const id = nextId.current++;
    setToasts((t) => [...t, { id, kind, message, detail }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 8000 : 3500);
  };

  return (
    <ToastCtx.Provider
      value={{
        success: (m) => push("success", m),
        error: (m, d) => push("error", m, d),
      }}
    >
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-96 max-w-[90vw] flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cn(
              "pointer-events-auto rounded-md px-4 py-3 text-sm shadow-lg",
              t.kind === "success"
                ? "bg-emerald-600 text-white"
                : "bg-red-600 text-white",
            )}
          >
            <p className="font-medium">{t.message}</p>
            {t.detail && <p className="mt-1 break-words text-xs opacity-90">{t.detail}</p>}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

// ---- row action menu ----

/**
 * "⋯" menu for table rows. Rendered with position: fixed so it is not clipped
 * by the Table's overflow-x-auto scroll container.
 */
export function RowMenu<K extends string>({
  items,
  onSelect,
  width = "w-40",
}: {
  items: ReadonlyArray<readonly [K, string]>;
  onSelect: (kind: K) => void;
  width?: string;
}) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; right: number }>({ top: 0, right: 0 });
  const btnRef = useRef<HTMLButtonElement>(null);

  const toggle = () => {
    if (!open && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect();
      setPos({ top: r.bottom + 4, right: Math.max(8, window.innerWidth - r.right) });
    }
    setOpen(!open);
  };

  // The menu is anchored to the viewport; close it if the page moves.
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  return (
    <>
      <button
        ref={btnRef}
        onClick={toggle}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        className="rounded px-2 py-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
        aria-label="Actions"
      >
        ⋯
      </button>
      {open && (
        <div
          style={{ position: "fixed", top: pos.top, right: pos.right }}
          className={cn(
            "z-40 rounded-md border border-slate-200 bg-white py-1 shadow-lg dark:border-slate-700 dark:bg-slate-800",
            width,
          )}
        >
          {items.map(([kind, label]) => (
            <button
              key={kind}
              onClick={() => onSelect(kind)}
              className={cn(
                "block w-full px-3 py-1.5 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-700",
                kind === "delete" ? "text-red-600 dark:text-red-400" : "text-slate-700 dark:text-slate-200",
              )}
            >
              {label}
            </button>
          ))}
        </div>
      )}
    </>
  );
}

// ---- tables ----

export function Table({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[40rem] text-left text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500 dark:border-slate-700 dark:text-slate-400">
            {head}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{children}</tbody>
      </table>
    </div>
  );
}

export const Th = ({ children, className }: { children?: ReactNode; className?: string }) => (
  <th className={cn("px-3 py-2 font-medium", className)}>{children}</th>
);

export const Td = ({ children, className, colSpan }: { children?: ReactNode; className?: string; colSpan?: number }) => (
  <td colSpan={colSpan} className={cn("px-3 py-2.5 align-middle text-slate-700 dark:text-slate-300", className)}>
    {children}
  </td>
);
