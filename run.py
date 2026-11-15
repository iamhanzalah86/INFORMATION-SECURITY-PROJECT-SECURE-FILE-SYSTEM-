import os

from app import create_app

app = create_app()


if __name__ == "__main__":
    # HTTPS=1 in .env serves https://127.0.0.1:5000 with a self-signed certificate
    # (the browser shows a warning once; choose "Advanced" -> "Proceed").
    https = os.environ.get("HTTPS", "0").strip() == "1"
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "1") == "1",
        ssl_context="adhoc" if https else None,
    )
