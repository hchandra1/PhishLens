# PhishLens UI

Next.js app for PhishLens. See the [project README](../README.md).

```bash
npm ci
PHISHLENS_API_URL=http://127.0.0.1:8000 npm run dev   # backend must be running
```

In development the browser only talks to this app, and `/api/*` is forwarded to the Python
backend (`next.config.ts`), so no CORS is needed. In production (`NEXT_OUTPUT=export`) the UI
is exported as static files and the backend serves them next to `/api/*` (see the root
`Dockerfile`). `src/app/outlook/` is the Outlook add-in task pane. Types in `src/lib/types.ts`
mirror the backend's Pydantic `Verdict` contract. Sample emails in `public/samples/` come from
the backend's test fixtures.
