// Form primitives for the ACLs Beta editor: a chip multi-select with grouped
// suggestions (SelectorPicker) and a validated ports field (PortsInput).

import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Badge, Input, cn } from "../../components/ui";
import { classify, parsePorts, splitDst, type Issue, type SelectorKind, type SelectorOption } from "./model";

type Tone = "gray" | "green" | "yellow" | "red" | "blue" | "purple";

export function kindTone(kind: SelectorKind): Tone {
  switch (kind) {
    case "user":
      return "green";
    case "group":
      return "blue";
    case "tag":
      return "purple";
    case "host":
      return "yellow";
    case "unknown":
      return "red";
    default:
      return "gray";
  }
}

const KIND_LABEL: Record<SelectorKind, string> = {
  user: "Users",
  group: "Groups",
  tag: "Tags",
  host: "Hosts",
  autogroup: "Autogroups",
  cidr: "Addresses",
  wildcard: "Wildcard",
  unknown: "Other",
};

/** One selector as a chip; `suffix` renders the ports part of a destination. */
export function SelectorChip({
  value,
  hosts,
  suffix,
  warn,
  onRemove,
}: {
  value: string;
  hosts?: Record<string, string>;
  suffix?: string;
  warn?: string;
  onRemove?: () => void;
}) {
  return (
    <Badge tone={kindTone(classify(value, hosts))} title={warn}>
      {warn && <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-amber-500" aria-label="warning" />}
      <span className="font-mono">{value}</span>
      {suffix !== undefined && <span className="ml-0.5 font-mono opacity-60">:{suffix}</span>}
      {onRemove && (
        <button type="button" className="ml-1 opacity-70 hover:opacity-100" onClick={onRemove} aria-label={`remove ${value}`}>
          ✕
        </button>
      )}
    </Badge>
  );
}

export function SelectorPicker({
  value,
  onChange,
  options,
  validate,
  hosts,
  placeholder,
  autoFocus,
  disabled,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  options: SelectorOption[];
  validate: (raw: string) => Issue | null;
  hosts?: Record<string, string>;
  placeholder?: string;
  autoFocus?: boolean;
  disabled?: boolean;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(-1);
  const [navigated, setNavigated] = useState(false); // arrow keys used since last keystroke
  const [note, setNote] = useState<Issue | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return options
      .filter((o) => !value.includes(o.value))
      .filter((o) => !q || o.value.toLowerCase().includes(q) || o.hint?.toLowerCase().includes(q))
      .slice(0, 60);
  }, [options, value, query]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  useEffect(() => {
    setHighlight(filtered.length ? 0 : -1);
    setNavigated(false);
  }, [filtered.length, query]);

  const add = (raw: string) => {
    let s = raw.trim();
    if (!s) return;
    if (/^(tag|group|autogroup):/i.test(s)) s = s.toLowerCase();
    // A pasted "selector:ports" destination: keep the selector, point at the Ports field.
    let hint: Issue | null = null;
    if (s.includes(":")) {
      const { selector, ports, error } = splitDst(s);
      if (!error && ports && classify(selector, hosts) !== "unknown") {
        s = selector;
        hint = { level: "warn", text: `Dropped ":${ports}" — ports go in the Ports field.` };
      }
    }
    const issue = validate(s);
    if (issue?.level === "error") {
      setNote(issue);
      return;
    }
    if (!value.includes(s)) onChange([...value, s]);
    setNote(hint ?? issue);
    setQuery("");
    setOpen(false);
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") {
      if (open) {
        e.preventDefault();
        e.stopPropagation(); // keep the surrounding Modal open
        setOpen(false);
      }
      return;
    }
    const highlighted = open && highlight >= 0 && highlight < filtered.length ? filtered[highlight] : undefined;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setOpen(true);
      setNavigated(true);
      setHighlight((h) => Math.min(h + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setNavigated(true);
      setHighlight((h) => Math.max(h - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      // Arrow-selected suggestion wins; otherwise typed text (or the single match when nothing was typed).
      if (highlighted && (navigated || !query.trim())) add(highlighted.value);
      else if (query.trim()) add(query);
    } else if (e.key === "Backspace" && query === "" && value.length > 0) {
      onChange(value.slice(0, -1));
    } else if (e.key === "Tab" && highlighted && query.trim()) {
      e.preventDefault();
      setQuery(highlighted.value);
    }
  };

  // group filtered options by kind, preserving order of first appearance
  const groups = useMemo(() => {
    const out: Array<{ kind: SelectorKind; items: Array<{ o: SelectorOption; idx: number }> }> = [];
    filtered.forEach((o, idx) => {
      let g = out.find((x) => x.kind === o.kind);
      if (!g) {
        g = { kind: o.kind, items: [] };
        out.push(g);
      }
      g.items.push({ o, idx });
    });
    return out;
  }, [filtered]);

  return (
    <div ref={rootRef} className="relative">
      <div
        className={cn(
          "flex min-h-[2.4rem] flex-wrap items-center gap-1.5 rounded-md border border-slate-300 bg-white px-2 py-1.5",
          "focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500 dark:border-slate-600 dark:bg-slate-800",
          disabled && "opacity-60",
        )}
        onClick={() => inputRef.current?.focus()}
      >
        {value.map((v) => {
          const opt = options.find((o) => o.value === v);
          const issue = validate(v);
          return (
            <SelectorChip
              key={v}
              value={v}
              hosts={hosts}
              warn={opt?.warn ?? (issue ? issue.text : undefined)}
              onRemove={disabled ? undefined : () => onChange(value.filter((x) => x !== v))}
            />
          );
        })}
        <input
          ref={inputRef}
          value={query}
          disabled={disabled}
          autoFocus={autoFocus}
          placeholder={value.length === 0 ? placeholder : ""}
          onChange={(e) => {
            setQuery(e.target.value);
            setOpen(true);
            setNote(null);
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={onKey}
          className="min-w-[8rem] flex-1 bg-transparent text-sm text-slate-900 outline-none placeholder:text-slate-400 dark:text-slate-100"
        />
      </div>
      {note && (
        <p className={cn("mt-1 text-xs", note.level === "error" ? "text-red-600 dark:text-red-400" : "text-amber-700 dark:text-amber-300")}>
          {note.text}
        </p>
      )}
      {open && !disabled && (filtered.length > 0 || query.trim()) && (
        <ul
          role="listbox"
          className="absolute z-20 mt-1 max-h-64 w-full overflow-auto rounded-md border border-slate-200 bg-white py-1 text-sm shadow-lg dark:border-slate-700 dark:bg-slate-900"
        >
          {groups.map((g) => (
            <li key={g.kind}>
              <p className="px-3 pb-0.5 pt-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">{KIND_LABEL[g.kind]}</p>
              <ul>
                {g.items.map(({ o, idx }) => (
                  <li
                    key={o.value}
                    role="option"
                    aria-selected={idx === highlight}
                    onMouseEnter={() => setHighlight(idx)}
                    onMouseDown={(e) => {
                      e.preventDefault();
                      add(o.value);
                    }}
                    className={cn(
                      "flex cursor-pointer items-center justify-between gap-3 px-3 py-1.5",
                      idx === highlight ? "bg-indigo-50 dark:bg-indigo-950/60" : "",
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <span className={cn("inline-block h-2 w-2 rounded-full", dotClass(o.kind))} />
                      <span className="font-mono text-slate-800 dark:text-slate-100">{o.value}</span>
                    </span>
                    <span className={cn("truncate text-xs", o.warn ? "text-amber-600 dark:text-amber-300" : "text-slate-400")}>
                      {o.warn ?? o.hint}
                    </span>
                  </li>
                ))}
              </ul>
            </li>
          ))}
          {query.trim() && !filtered.some((o) => o.value === query.trim()) && (
            <li
              role="option"
              aria-selected={false}
              onMouseDown={(e) => {
                e.preventDefault();
                add(query);
              }}
              className="cursor-pointer border-t border-slate-100 px-3 py-1.5 text-slate-600 dark:border-slate-800 dark:text-slate-300"
            >
              Add <span className="font-mono">{query.trim()}</span>
              <span className="ml-2 text-xs text-slate-400">user@, group:, tag:, host, IP or CIDR</span>
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

function dotClass(kind: SelectorKind): string {
  switch (kindTone(kind)) {
    case "green":
      return "bg-emerald-500";
    case "blue":
      return "bg-sky-500";
    case "purple":
      return "bg-violet-500";
    case "yellow":
      return "bg-amber-500";
    case "red":
      return "bg-red-500";
    default:
      return "bg-slate-400";
  }
}

export function PortsInput({
  value,
  onChange,
  disabled,
  mixed,
}: {
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  mixed?: boolean;
}) {
  const parsed = value.trim() === "" ? null : parsePorts(value);
  return (
    <div>
      <Input
        value={value}
        disabled={disabled}
        placeholder={mixed ? "mixed — leave empty to keep each destination's ports" : "* or 22, 80-90, 443"}
        onChange={(e) => onChange(e.target.value)}
        className="font-mono"
      />
      {parsed && !parsed.ok && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{parsed.error}</p>}
    </div>
  );
}
