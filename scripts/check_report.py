"""Check report structure and local links without a browser or network access."""

import argparse
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.ids = []
        self.scripts = []
        self.current_script = None
        self.cards = 0
        self.csp = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "a":
            self.links.append(attrs.get("href", ""))
        if "data-scenario" in attrs:
            self.cards += 1
        if tag == "script":
            if "src" in attrs:
                raise ValueError("report depends on an external script")
            self.current_script = ""
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy":
            self.csp = attrs.get("content")

    def handle_data(self, data):
        if self.current_script is not None:
            self.current_script += data

    def handle_endtag(self, tag):
        if tag == "script" and self.current_script is not None:
            self.scripts.append(self.current_script)
            self.current_script = None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--extract-script", type=Path)
    args = parser.parse_args()
    document = ReportParser()
    document.feed(args.report.read_text(encoding="utf-8"))
    if len(document.ids) != len(set(document.ids)):
        raise ValueError("duplicate element ids")
    if not document.csp or len(document.scripts) != 1 or "print-report" not in document.ids:
        raise ValueError("report controls or CSP missing")
    if document.cards and "scenario-filter" not in document.ids:
        raise ValueError("scenario filter missing")
    for link in document.links:
        if ":" in link or "/" in link or "\\" in link or not (args.report.parent / link).is_file():
            raise ValueError("broken or nonlocal report link")
    script = document.scripts[0]
    script_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    if "'sha256-" + script_hash + "'" not in document.csp:
        raise ValueError("script hash does not match content security policy")
    if args.extract_script:
        with args.extract_script.open("x", encoding="utf-8") as handle:
            handle.write(script)
    print({"scenario_cards": document.cards, "local_links": len(document.links),
           "script_csp_verified": True, "visual_browser_check": "not performed"})


if __name__ == "__main__":
    main()
