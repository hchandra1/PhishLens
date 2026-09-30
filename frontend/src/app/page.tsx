import { Analyzer } from "@/components/Analyzer";

export default function Home() {
  return (
    <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-10 sm:px-6">
      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Is this email safe?</h1>
        <p className="mt-2 text-zinc-600 dark:text-zinc-400">
          Paste a suspicious email or upload it as a file. PhishLens checks who really sent it, where
          its links go, and what its attachments are, then explains what it found in plain English.
        </p>
      </header>
      <Analyzer />
    </main>
  );
}
