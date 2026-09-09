"""Pinned MCP 2025-06-18 stdio tools subset for the synthetic ticket service.

Supports initialize, initialized, ping, tools/list, tools/call; no sampling,
arbitrary commands, external servers, or model-provider calls.
"""

import os
import sys

from .common import MAX_MESSAGE, canonical, decode, local_request

VERSION = "2025-06-18"
SCHEMA = {"type": "object", "additionalProperties": False,
    "required": ["identity", "ticket", "request_id"], "properties": {
        "identity": {"type": "string", "enum": ["agent", "child", "session"]},
        "ticket": {"type": "string", "enum": ["TICKET-001", "TICKET-002"]},
        "request_id": {"type": "string", "minLength": 1, "maxLength": 80},
        "approval_id": {"type": "string", "minLength": 1, "maxLength": 80}}}
TOOLS = [{"name": name, "description": description, "inputSchema": SCHEMA} for name, description in (
    ("update_ticket", "Increment one synthetic lab ticket; changes local test state."),
    ("enqueue_ticket", "Queue one synthetic ticket increment for the lab worker."))]


class Protocol:
    def __init__(self, config):
        self.config = config
        self.initialized = False
        self.ready = False
        self.calls = 0

    def handle(self, request):
        if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0"
                or not isinstance(request.get("method"), str)):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}
        identifier = request.get("id")
        method = request["method"]
        if "id" not in request:
            if method == "notifications/initialized" and self.initialized:
                self.ready = True
            return None
        if type(identifier) not in (str, int):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid id"}}
        response = {"jsonrpc": "2.0", "id": identifier}
        try:
            params = request.get("params", {})
            if method == "initialize" and not self.initialized:
                if params.get("protocolVersion") != VERSION:
                    raise ValueError("Unsupported pinned protocol version")
                self.initialized = True
                result = {"protocolVersion": VERSION, "capabilities": {"tools": {}},
                          "serverInfo": {"name": "tracebound-ticket-lab", "version": "0.1.0"}}
            elif method == "ping":
                result = {}
            elif not self.ready:
                raise ValueError("Initialization required")
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                if self.calls >= 20:
                    raise ValueError("Tool-call budget exhausted")
                result = self.call(params)
                self.calls += 1
            else:
                response["error"] = {"code": -32601, "message": "Method not found"}
                return response
            response["result"] = result
        except (ValueError, KeyError, TypeError):
            response["error"] = {"code": -32602, "message": "Invalid parameters or lifecycle"}
        except Exception:
            response["result"] = {"isError": True, "content": [{"type": "text",
                "text": "Dependency unavailable; execution outcome unknown"}],
                "structuredContent": {"http_status": None, "outcome": "unknown"}}
        return response

    def call(self, params):
        if params.get("name") not in ("update_ticket", "enqueue_ticket"):
            raise ValueError("Unknown tool")
        args = params["arguments"]
        if not isinstance(args, dict) or set(args) - set(SCHEMA["properties"]):
            raise ValueError("Unknown arguments")
        if (args["identity"] not in self.config["credentials"]
                or args["ticket"] not in ("TICKET-001", "TICKET-002")
                or not isinstance(args["request_id"], str) or not 1 <= len(args["request_id"]) <= 80):
            raise ValueError("Invalid bounded tool scope")
        if "approval_id" in args and (not isinstance(args["approval_id"], str)
                                      or not 1 <= len(args["approval_id"]) <= 80):
            raise ValueError("Invalid approval")
        payload = {"action": {"ticket": args["ticket"], "operation": "increment"},
                   "request_id": args["request_id"]}
        path = "/session-ticket" if args["identity"] == "session" else "/ticket"
        if "approval_id" in args:
            path = "/approved-ticket"
            payload["approval_id"] = args["approval_id"]
        if params["name"] == "enqueue_ticket":
            if args["identity"] != "agent" or "approval_id" in args:
                raise ValueError("Queue only supports the primary agent")
            path = "/queue"
        status, body = local_request(self.config["resource"], path, payload,
                                    self.config["credentials"][args["identity"]])
        structured = {"http_status": status, **body}
        return {"isError": status != 200, "structuredContent": structured,
                "content": [{"type": "text", "text": canonical(structured).decode()}]}


def main():
    protocol = Protocol(decode(os.environ.pop("TRACEBOUND_MCP_CONFIG").encode()))
    while True:
        raw = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
        if not raw:
            break
        if len(raw) > MAX_MESSAGE:
            break
        try:
            response = protocol.handle(decode(raw))
        except (ValueError, RecursionError):
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "Parse error"}}
        if response is not None:
            sys.stdout.buffer.write(canonical(response) + b"\n")
            sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()

