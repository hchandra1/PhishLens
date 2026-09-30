"use client";

interface Props {
  value: string;
  onChange: (code: string) => void;
  invalid: boolean;
}

export function AccessCodeField({ value, onChange, invalid }: Props) {
  return (
    <label className="block text-sm">
      <span className="font-medium">Access code</span>
      <span className="ml-2 text-zinc-500">This deployment is private. Ask your administrator for the code.</span>
      <input
        type="password"
        autoComplete="off"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={invalid}
        className={`mt-1 block w-full max-w-xs rounded-md border bg-transparent px-3 py-1.5 ${
          invalid ? "border-red-500" : "border-zinc-300 dark:border-zinc-700"
        }`}
      />
    </label>
  );
}
