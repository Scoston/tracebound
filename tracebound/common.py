"""Bounded JSON, private output, and explicit network boundaries."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_MESSAGE = 131072
MAX_ARTIFACT = 20 * 1024 * 1024


def canonical(value):
    """TraceBound JSON profile; deliberately not a claim of RFC 8785 support."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode(data, limit=MAX_MESSAGE):
    if len(data) > limit:
        raise ValueError("JSON exceeds configured limit")
    def reject(value):
        raise ValueError("non-finite JSON number")
    return json.loads(data, object_pairs_hook=_unique, parse_constant=reject)


def private_write(path, data):
    path = Path(path)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)


def new_directory(path):
    target = Path(path).absolute()
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    return target


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def local_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or not parsed.port or parsed.username or parsed.password
            or parsed.fragment or parsed.query):
        raise ValueError("lab transport must use literal IPv4 loopback")
    return url


def local_request(base, path, payload=None, token="", timeout=5):
    url = local_url(base + path)
    data = None if payload is None else canonical(payload)
    if data is not None and len(data) > MAX_MESSAGE:
        raise ValueError("request exceeds configured limit")
    request = Request(url, data=data, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    })
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(MAX_MESSAGE + 1)
        return response.status, decode(body)

