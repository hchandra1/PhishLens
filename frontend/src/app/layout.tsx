import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishLens: is this email safe?",
  description: "Explainable phishing checks for small teams.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full flex-col">
        {children}
        <footer className="py-6 text-center text-xs text-zinc-500">
          PhishLens helps you decide. When in doubt, ask your IT or security contact.
        </footer>
      </body>
    </html>
  );
}
