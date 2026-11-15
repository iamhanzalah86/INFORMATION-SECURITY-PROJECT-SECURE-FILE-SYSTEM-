"""Serves the built React app (frontend/dist) for every non-API URL."""

from pathlib import Path

from flask import Blueprint, abort, jsonify, send_from_directory

DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

spa = Blueprint("spa", __name__)


@spa.get("/healthz")
def healthz():
    return jsonify(status="ok")


@spa.get("/", defaults={"path": ""})
@spa.get("/<path:path>")
def serve(path):
    if path.startswith("api/"):
        abort(404)

    if not (DIST / "index.html").is_file():
        return (
            "<h2>Frontend not built yet</h2>"
            "<p>Run <code>npm install &amp;&amp; npm run build</code> inside the "
            "<code>frontend</code> folder, or use <code>npm run dev</code> and open "
            "http://localhost:5173.</p>",
            503,
        )

    if path:
        target = (DIST / path).resolve()
        if DIST.resolve() in target.parents and target.is_file():
            return send_from_directory(DIST, path)

    return send_from_directory(DIST, "index.html")
