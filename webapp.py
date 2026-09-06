#!/usr/bin/env python3
"""Small local web UI for anoncsv, using only the Python standard library."""

from __future__ import annotations

import html
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from anoncsv import anonymize_text, parse_mapping

MAX_REQUEST_BYTES = 5 * 1024 * 1024


PAGE = """<!doctype html>
<html lang="cs">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>anoncsv | Anonymizace CSV</title>
  <style>
    :root { color-scheme: light; --ink: #18302b; --muted: #5c706b; --paper: #f5f0e8; --card: #fffdf8; --accent: #d65b3d; --line: #d8d0c3; }
    * { box-sizing: border-box; }
    body { margin: 0; background: radial-gradient(circle at 85% 10%, #f5c9a7 0, transparent 28%), var(--paper); color: var(--ink); font: 16px/1.5 Georgia, serif; }
    main { max-width: 900px; margin: 0 auto; padding: 48px 20px 64px; }
    .eyebrow { color: var(--accent); font: 700 13px/1.2 monospace; letter-spacing: .12em; text-transform: uppercase; }
    h1 { max-width: 680px; margin: 12px 0; font-size: clamp(40px, 8vw, 76px); line-height: .95; letter-spacing: -.05em; }
    .intro { max-width: 620px; color: var(--muted); font-size: 19px; }
    form { margin-top: 32px; padding: 24px; background: var(--card); border: 1px solid var(--line); border-radius: 18px; box-shadow: 0 18px 45px #604a2712; }
    label { display: block; margin: 16px 0 7px; font: 700 13px/1.2 monospace; letter-spacing: .04em; text-transform: uppercase; }
    textarea, input { width: 100%; border: 1px solid var(--line); border-radius: 10px; padding: 12px; background: #fff; color: var(--ink); font: 14px/1.45 monospace; }
    input[type=file] { padding: 10px; font-family: monospace; }
    textarea { min-height: 220px; resize: vertical; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    button { margin-top: 22px; border: 0; border-radius: 999px; padding: 13px 22px; background: var(--accent); color: #fff; cursor: pointer; font: 700 15px monospace; }
    button:hover { filter: brightness(.94); }
    .note { color: var(--muted); font-size: 14px; }
    .result { margin-top: 28px; padding: 20px 24px; background: #e1eee4; border-radius: 14px; }
    .result a { color: var(--ink); font-weight: 700; }
    .error { margin-top: 24px; padding: 14px 18px; border-left: 4px solid var(--accent); background: #fff0e9; }
    @media (max-width: 600px) { .grid { grid-template-columns: 1fr; } main { padding-top: 30px; } }
  </style>
</head>
<body>
<main>
  <div class="eyebrow">anoncsv / lokální nástroj</div>
  <h1>Odstraň citlivost z dat.</h1>
  <p class="intro">Vlož CSV, nech citlivé sloupce automaticky rozpoznat a stáhni anonymizovaný výsledek. Data neopouštějí tento počítač.</p>
  {message}
  <form method="post">
    <label for="csv">CSV data</label>
    <input id="file" type="file" accept=".csv,text/csv">
    <textarea id="csv" name="csv" required placeholder="name,email,city&#10;Alice,alice@example.com,Prague">{csv}</textarea>
    <div class="grid">
      <div>
        <label for="salt">Salt</label>
        <input id="salt" name="salt" value="{salt}" placeholder="tajny-klic">
      </div>
      <div>
        <label for="delimiter">Oddělovač</label>
        <input id="delimiter" name="delimiter" value="," maxlength="1">
      </div>
    </div>
    <label for="mapping">Ruční mapování <span class="note">(např. customer_id=token, jedno na řádek)</span></label>
    <textarea id="mapping" name="mapping" style="min-height: 90px" placeholder="customer_id=token">{mapping}</textarea>
    <p class="note">Podporované typy: email, phone, ip, name, token.</p>
    <button type="submit">Anonymizovat CSV</button>
  </form>
  {result}
</main>
<script>
  document.querySelector('#file').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (file) document.querySelector('#csv').value = await file.text();
  });
</script>
</body>
</html>"""

RESULTS: dict[str, str] = {}


def render_page(
    message: str = "",
    csv: str = "",
    salt: str = "",
    mapping: str = "",
    result: str = "",
) -> bytes:
    return (
        PAGE.replace("{message}", message)
        .replace("{csv}", html.escape(csv))
        .replace("{salt}", html.escape(salt))
        .replace("{mapping}", html.escape(mapping))
        .replace("{result}", result)
        .encode("utf-8")
    )


class AnonCsvHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/download/"):
            token = path.rsplit("/", 1)[-1]
            output = RESULTS.get(token)
            if output is None:
                self._send(404, b"Vysledek nebyl nalezen nebo uz vyprsel.")
            else:
                self._send_csv(output)
            return
        self._send(200, render_page())

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, b"Neplatna velikost pozadavku.")
            return
        if length > MAX_REQUEST_BYTES:
            self._send(413, b"CSV je prilis velke. Limit je 5 MB.")
            return
        fields = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        csv_text = fields.get("csv", [""])[0]
        salt = fields.get("salt", [""])[0] or secrets.token_hex(16)
        mapping_text = fields.get("mapping", [""])[0]
        delimiter = fields.get("delimiter", [","])[0] or ","
        try:
            mapping = parse_mapping(
                [line.strip() for line in mapping_text.splitlines() if line.strip()]
            )
            output, count, used = anonymize_text(csv_text, mapping, salt, delimiter)
            token = secrets.token_urlsafe(18)
            if len(RESULTS) >= 20:
                RESULTS.pop(next(iter(RESULTS)))
            RESULTS[token] = output
            result = (
                '<section class="result"><strong>Hotovo: '
                f"{count} řádků, {len(used)} citlivých sloupců.</strong>"
                f'<p><a href="/download/{token}" download>Stáhnout anonymizované CSV</a></p>'
                f"<pre>{html.escape(output)}</pre></section>"
            )
            self._send(200, render_page("", csv_text, salt, mapping_text, result))
            print(f"Anonymizováno řádků: {count}; sloupce: {used}")
        except (ValueError, UnicodeDecodeError) as error:
            message = f'<div class="error">{html.escape(str(error))}</div>'
            self._send(400, render_page(message, csv_text, salt, mapping_text))

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_csv(self, output: str) -> None:
        body = output.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="anonymized.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    server = HTTPServer(("127.0.0.1", 8000), AnonCsvHandler)
    print("anoncsv běží na http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer ukončen.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
