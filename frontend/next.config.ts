import type { NextConfig } from "next";

// Production (NEXT_OUTPUT=export): a static site that the Python backend serves next to
// /api/*, so one container hosts everything. Development: `next dev` forwards /api/* to
// the backend, so the browser only ever talks to one origin and no CORS is needed.
const exporting = process.env.NEXT_OUTPUT === "export";
const backend = process.env.PHISHLENS_API_URL ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = exporting
  ? // trailingSlash emits outlook/index.html, which the backend serves for /outlook/.
    { output: "export", trailingSlash: true }
  : {
      async rewrites() {
        return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
      },
    };

export default nextConfig;
