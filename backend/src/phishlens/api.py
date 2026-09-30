"""HTTP API, and in production the static UI.

POST /api/analyze            body is the email: raw .eml bytes (message/rfc822, text/plain,
                             application/octet-stream) or JSON {"raw": "<email source>"}.
GET  /api/health             liveness, which optional checks are on, whether a code is needed.
GET  /outlook/manifest.xml   Outlook add-in manifest pointing at this deployment.
GET  /*                      the exported UI, when PHISHLENS_STATIC_DIR is set.

Privacy: emails are processed in memory and never written to disk, stored, or
logged; only the verdict label and score are logged. The body is read as a stream
(not multipart, which spools large uploads to temporary files) with a size cap.

Abuse controls for a public deployment: per-client rate limiting on analysis, and an
optional access code (PHISHLENS_ACCESS_CODE) so strangers can't spend API credits.
"""

from __future__ import annotations

import hmac
import json
import logging
import math
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from xml.sax.saxutils import escape

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from phishlens.analyzers import (
    DomainAgeAnalyzer,
    LlmContentAnalyzer,
    SafeBrowsingAnalyzer,
    VirusTotalAnalyzer,
    default_analyzers,
)
from phishlens.engine import analyze
from phishlens.models import Analyzer, Verdict
from phishlens.parser import EmailParseError, parse_email
from phishlens.ratelimit import RateLimiter, parse_rate

logger = logging.getLogger("phishlens.api")

MAX_BODY_BYTES = 10 * 1024 * 1024
RAW_TYPES = {"message/rfc822", "text/plain", "application/octet-stream"}
ACCESS_CODE_HEADER = "X-Access-Code"

_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
# Outlook shows the add-in page in a frame and loads Office.js from Microsoft's CDN.
_OUTLOOK_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://appsforoffice.microsoft.com; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self' https://*.microsoft.com https://*.office.com https://*.office365.com; "
    "frame-src https://*.office.com https://*.office365.com https://*.microsoft.com "
    "https://*.oaspapps.com; "
    "base-uri 'none'; form-action 'none'; frame-ancestors https://*.office.com "
    "https://*.office365.com https://*.outlook.com https://*.live.com https://*.microsoft.com"
)


@dataclass(frozen=True)
class Settings:
    access_code: str | None = None
    rate_limit: str = "30/minute"
    proxy_hops: int = 0
    """How many trusted proxies add themselves to X-Forwarded-For (e.g. 1 on Render)."""
    static_dir: Path | None = None
    public_url: str | None = None

    @classmethod
    def from_env(cls) -> Settings:
        static = os.environ.get("PHISHLENS_STATIC_DIR")
        return cls(
            access_code=os.environ.get("PHISHLENS_ACCESS_CODE") or None,
            rate_limit=os.environ.get("PHISHLENS_RATE_LIMIT", "30/minute"),
            proxy_hops=int(os.environ.get("PHISHLENS_PROXY_HOPS", "0")),
            static_dir=Path(static) if static else None,
            public_url=(os.environ.get("PHISHLENS_PUBLIC_URL") or "").rstrip("/") or None,
        )


def optional_checks(analyzers: list[Analyzer]) -> dict[str, bool]:
    """Which opt-in checks are configured. Never exposes keys or settings."""
    status = {}
    for analyzer in analyzers:
        if isinstance(analyzer, (LlmContentAnalyzer, DomainAgeAnalyzer)):
            status[analyzer.name] = analyzer.enabled
        elif isinstance(analyzer, (SafeBrowsingAnalyzer, VirusTotalAnalyzer)):
            status[analyzer.name] = bool(analyzer.api_key)
    return status


def create_app(
    analyzers: list[Analyzer] | None = None, settings: Settings | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    limiter = RateLimiter(*parse_rate(settings.rate_limit))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Built once so HTTP clients and caches are shared across requests.
        app.state.analyzers = analyzers if analyzers is not None else default_analyzers()
        yield

    app = FastAPI(title="PhishLens", version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        else:
            outlook = request.url.path.startswith("/outlook")
            response.headers["Content-Security-Policy"] = _OUTLOOK_CSP if outlook else _CSP
            if not outlook:
                response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/api/health")
    def health(request: Request) -> dict:
        return {
            "status": "ok",
            "optional_checks": optional_checks(request.app.state.analyzers),
            "access_code_required": settings.access_code is not None,
        }

    @app.post("/api/analyze")
    async def analyze_email(request: Request) -> Verdict:
        # Rate limit first, so wrong access codes count too and can't be brute-forced.
        retry_after = limiter.check(client_ip(request, settings.proxy_hops))
        if retry_after is not None:
            raise HTTPException(
                status_code=429,
                detail="Too many emails checked in a short time. Please wait a moment.",
                headers={"Retry-After": str(math.ceil(retry_after))},
            )
        _check_access_code(request, settings)
        raw = await _read_email(request)
        try:
            parsed = parse_email(raw)
        except EmailParseError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        started = time.perf_counter()
        verdict = await run_in_threadpool(analyze, parsed, request.app.state.analyzers)
        logger.info(
            "analyzed email: label=%s score=%s signals=%d in %.0f ms",
            verdict.label.value, verdict.score, len(verdict.signals),
            (time.perf_counter() - started) * 1000,
        )  # fmt: skip
        return verdict

    @app.get("/outlook/manifest.xml")
    def outlook_manifest(request: Request) -> Response:
        base = escape(settings.public_url or _base_url(request, settings.proxy_hops))
        template = files("phishlens").joinpath("outlook_manifest.xml").read_text("utf-8")
        return Response(template.replace("BASE_URL", base), media_type="application/xml")

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def api_not_found(path: str) -> JSONResponse:
        # Keep unknown /api/* paths from falling through to the UI's static files.
        return JSONResponse({"detail": "Not found."}, status_code=404)

    if settings.static_dir:
        app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="ui")
    return app


def client_ip(request: Request, proxy_hops: int) -> str:
    """The caller's address. X-Forwarded-For is only trusted for the configured number of
    proxy hops, counted from the right, since clients can put anything on the left."""
    peer = request.client.host if request.client else "unknown"
    if proxy_hops <= 0:
        return peer
    forwarded = [
        p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()
    ]
    return forwarded[-proxy_hops] if len(forwarded) >= proxy_hops else peer


def _base_url(request: Request, proxy_hops: int) -> str:
    scheme = request.url.scheme
    if proxy_hops > 0:
        scheme = request.headers.get("x-forwarded-proto", scheme).split(",")[0].strip()
    return f"{scheme}://{request.url.netloc}"


def _check_access_code(request: Request, settings: Settings) -> None:
    if settings.access_code is None:
        return
    given = request.headers.get(ACCESS_CODE_HEADER, "")
    if not hmac.compare_digest(given.encode(), settings.access_code.encode()):
        raise HTTPException(status_code=401, detail="Enter a valid access code to check emails.")


async def _read_email(request: Request) -> bytes | str:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type not in RAW_TYPES and content_type != "application/json":
        raise HTTPException(
            status_code=415,
            detail="Send the email as raw source (message/rfc822 or text/plain) or as JSON "
            '{"raw": "..."}.',
        )
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _too_large()

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise _too_large()

    if content_type != "application/json":
        return bytes(body)
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail="Request body is not valid JSON.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("raw"), str):
        raise HTTPException(status_code=422, detail='Expected JSON of the form {"raw": "..."}.')
    return payload["raw"]


def _too_large() -> HTTPException:
    return HTTPException(
        status_code=413, detail=f"Email is larger than {MAX_BODY_BYTES // (1024 * 1024)} MB."
    )


app = create_app()
