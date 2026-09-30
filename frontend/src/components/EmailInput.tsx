"use client";

import { useRef, useState } from "react";

const SAMPLES = [
  { file: "obvious-phish.eml", label: "Obvious phish" },
  { file: "ceo-fraud.eml", label: "CEO fraud" },
  { file: "lookalike-domain.eml", label: "Look-alike domain" },
  { file: "prompt-injection.eml", label: "AI prompt injection" },
  { file: "legitimate-invoice.eml", label: "Legitimate invoice" },
];

const MAX_BYTES = 10 * 1024 * 1024;

interface Props {
  busy: boolean;
  onAnalyze: (source: string | ArrayBuffer) => void;
}

export function EmailInput({ busy, onAnalyze }: Props) {
  const [text, setText] = useState("");
  const [file, setFile] = useState<{ name: string; data: ArrayBuffer } | null>(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  async function acceptFile(picked: File | undefined) {
    if (!picked) return;
    if (picked.size > MAX_BYTES) {
      setError("That file is larger than 10 MB.");
      return;
    }
    setError(null);
    setText("");
    setFile({ name: picked.name, data: await picked.arrayBuffer() });
  }

  async function loadSample(name: string) {
    const response = await fetch(`/samples/${name}`);
    setFile(null);
    setError(null);
    setText(await response.text());
  }

  const ready = (file !== null || text.trim() !== "") && !busy;

  return (
    <section aria-labelledby="input-heading" className="space-y-4">
      <h2 id="input-heading" className="sr-only">
        Email to check
      </h2>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          acceptFile(e.dataTransfer.files[0]);
        }}
        className={`rounded-xl border-2 border-dashed p-1 transition-colors ${
          dragging ? "border-blue-500 bg-blue-50 dark:bg-blue-950/40" : "border-zinc-300 dark:border-zinc-700"
        }`}
      >
        {file ? (
          <div className="flex items-center justify-between gap-4 p-4">
            <p className="text-sm">
              <span className="font-medium">{file.name}</span>{" "}
              <span className="text-zinc-500">({Math.ceil(file.data.byteLength / 1024)} KB)</span>
            </p>
            <button type="button" onClick={() => setFile(null)} className="text-sm text-blue-700 underline dark:text-blue-400">
              Remove
            </button>
          </div>
        ) : (
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={"Paste the email's full original source here (starts with lines like “From:” and “Received:”),\nor drop a .eml file."}
            aria-label="Email source"
            spellCheck={false}
            className="block h-56 w-full resize-y rounded-lg bg-transparent p-3 font-mono text-xs leading-relaxed outline-none"
          />
        )}
      </div>

      {error && <p role="alert" className="text-sm text-red-700 dark:text-red-400">{error}</p>}

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          disabled={!ready}
          onClick={() => onAnalyze(file ? file.data : text)}
          className="rounded-lg bg-blue-700 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Checking…" : "Check this email"}
        </button>
        <button
          type="button"
          onClick={() => fileInput.current?.click()}
          className="rounded-lg border border-zinc-300 px-4 py-2.5 text-sm font-medium hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800"
        >
          Upload .eml file
        </button>
        <input
          ref={fileInput}
          type="file"
          accept=".eml,message/rfc822,text/plain"
          className="hidden"
          onChange={(e) => {
            acceptFile(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
        <label className="ml-auto flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-400">
          Try an example:
          <select
            defaultValue=""
            onChange={(e) => e.target.value && loadSample(e.target.value)}
            className="rounded-md border border-zinc-300 bg-transparent px-2 py-1.5 dark:border-zinc-700"
          >
            <option value="" disabled>
              Choose…
            </option>
            {SAMPLES.map((s) => (
              <option key={s.file} value={s.file}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <details className="text-sm text-zinc-600 dark:text-zinc-400">
        <summary className="cursor-pointer font-medium text-zinc-800 dark:text-zinc-200">
          How do I get an email&apos;s original source?
        </summary>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li><strong>Gmail:</strong> open the email, click ⋮ (More) → <em>Show original</em> → <em>Copy to clipboard</em>.</li>
          <li><strong>Outlook (web):</strong> open the email, click ⋯ → <em>View</em> → <em>View message source</em>.</li>
          <li><strong>Outlook (Windows):</strong> drag the email to your desktop to save it, then upload that file.</li>
          <li><strong>Apple Mail:</strong> <em>View</em> → <em>Message</em> → <em>Raw Source</em>, or <em>File</em> → <em>Save As</em> (Raw Message Source).</li>
        </ul>
        <p className="mt-2">Pasting only the visible text still works, but we can&apos;t check who really sent it.</p>
      </details>
    </section>
  );
}
