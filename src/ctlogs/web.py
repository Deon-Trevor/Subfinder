from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

LOGGER = logging.getLogger("ctlogs.web")

INDEX = "index.html"

# Explicit name -> content type, so a stray file dropped in web/ is not servable.
ASSETS: dict[str, str] = {
    "app.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    # robots.txt keeps crawlers off /v1/search and off the "?apex=" form of the
    # page. Both spend the shared 1000-reads-per-IP-per-day allowance, and a
    # crawler following every result link would spend it on nobody's behalf.
    "robots.txt": "text/plain; charset=utf-8",
}


def frontend_directory() -> Path | None:
    """Locate the built frontend, or None when it was not shipped."""
    override = os.environ.get("CTLOGS_WEB_DIR")
    root = Path(override) if override else Path(__file__).resolve().parents[2] / "web"
    return root if (root / INDEX).is_file() else None


def _serve(path: Path, media_type: str) -> Callable[[], Awaitable[FileResponse]]:
    # A factory rather than a closure over the loop variable: a route function
    # with parameters would have them read as query parameters by FastAPI.
    async def route() -> FileResponse:
        if not path.is_file():
            raise HTTPException(status_code=404, detail="not found")
        # The page and its two assets ship together, so revalidate rather than
        # let a browser pair new markup with a cached script.
        return FileResponse(
            path,
            media_type=media_type,
            headers={"Cache-Control": "no-cache"},
        )

    return route


def mount_frontend(app: FastAPI) -> bool:
    """Serve the frontend from the same origin as the API.

    The page is a handful of static files, registered as explicit routes rather
    than a StaticFiles mount: create_app mounts the MCP app at "/", and a second
    directory mount on that prefix would swallow /mcp. Named paths cannot
    shadow an API route.

    None of these routes consume the request allowance. GET /v1/search and
    POST /mcp share 1,000 successful reads per IP per UTC day, and opening the
    page must not spend any of it.
    """
    directory = frontend_directory()
    if directory is None:
        LOGGER.info("No frontend found; serving the API alone")
        return False

    routes = {INDEX: "text/html; charset=utf-8", **ASSETS}
    for name, media_type in routes.items():
        app.add_api_route(
            "/" if name == INDEX else f"/{name}",
            _serve(directory / name, media_type),
            methods=["GET"],
            include_in_schema=False,
        )

    LOGGER.info("Serving the frontend from %s", directory)
    return True
