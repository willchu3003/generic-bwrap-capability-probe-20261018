"""Nonroot T transport. Health never dispatches. Only synthetic result data."""
import base64
import ctypes as C
import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from common import AUTH, DISPATCH, PUB, WORK, atomic_json, identity_ok, proc_status, read_json
from policy import DispatchLedger


def main():
    os.chdir(WORK / "trusted")
    boot = read_json(PUB / "boot.json")
    ledger = DispatchLedger(boot["run_id"], boot["boot_id"])
    dispatch_token = (AUTH / "token").read_text()
    status = proc_status()
    if not identity_ok(status, 10001, (10001, 10011, 10012, 10013)):
        raise RuntimeError("T transport identity precondition failed")
    libc = C.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE after exec/credential changes
        raise OSError(C.get_errno(), "PR_SET_DUMPABLE")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def log_message(self, *args):
            pass

        def reply(self, code, value):
            data = json.dumps(value, sort_keys=True).encode()
            if len(data) > 49152:
                code, data = 500, b'{"status":"INCONCLUSIVE","reason":"result bound"}'
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            uri = urlsplit(self.path)
            if uri.path == "/healthz" and not uri.query:
                self.reply(200, {"transport": "ready", "run_id": boot["run_id"],
                                 "boot_id": boot["boot_id"], "dispatched_this_boot": ledger.used})
            elif uri.path == "/result":
                try:
                    query = parse_qs(uri.query, strict_parsing=True, max_num_fields=2) if uri.query else {}
                except ValueError:
                    self.reply(400, {"error": "invalid fixed query"})
                    return
                manifest = read_json(PUB / "artifacts.json") if (PUB / "artifacts.json").exists() else {}
                if not query:
                    report = read_json(PUB / "result.json") if (PUB / "result.json").exists() else {"status": "WAITING_NO_AUTO_DISPATCH"}
                    self.reply(200, {"run_id": boot["run_id"], "boot_id": boot["boot_id"],
                                     "report": report, "artifacts": manifest})
                elif set(query) == {"artifact", "part"} and all(len(v) == 1 for v in query.values()):
                    name, part_text = query["artifact"][0], query["part"][0]
                    if name not in manifest or not part_text.isascii() or not part_text.isdecimal() or len(part_text) > 6:
                        self.reply(404, {"error": "unknown fixed artifact"})
                        return
                    part = int(part_text)
                    if part >= manifest[name]["parts"]:
                        self.reply(404, {"error": "unknown part"})
                        return
                    data = (PUB / "artifacts" / name).read_bytes()[part * 8192:(part + 1) * 8192]
                    self.reply(200, {"artifact": name, "part": part, "data_base64": base64.b64encode(data).decode(),
                                     "part_sha256": hashlib.sha256(data).hexdigest()})
                else:
                    self.reply(400, {"error": "fixed artifact/part parameters required"})
            else:
                self.reply(404, {"error": "unknown route"})

        def do_POST(self):
            length = self.headers.get("Content-Length", "")
            if (self.path != "/dispatch" or not length.isdecimal() or not 0 < int(length) <= 1024
                    or self.headers.get("Transfer-Encoding") is not None):
                self.reply(400, {"error": "fixed bounded dispatch required"})
                return
            supplied = self.headers.get("X-Probe-Dispatch", "")
            if not supplied.isascii() or not hmac.compare_digest(supplied, dispatch_token):
                self.reply(403, {"error": "dispatch control required"})
                return
            try:
                body = json.loads(self.rfile.read(int(length)))
                accepted = isinstance(body, dict) and ledger.accept(body)
            except (ValueError, TypeError):
                accepted = False
            if not accepted:
                self.reply(409, {"error": "wrong boot/run or already dispatched"})
                return
            atomic_json(DISPATCH / "once.json", {"run_id": boot["run_id"], "boot_id": boot["boot_id"]})
            self.reply(202, {"accepted": True, "run_id": boot["run_id"], "boot_id": boot["boot_id"]})

    server = HTTPServer(("0.0.0.0", boot["port"]), Handler)
    server.timeout = 0.2
    secret_fd = None
    while True:
        if secret_fd is None and (WORK / "trusted" / "dummy-secret").exists():
            secret_fd = os.open(WORK / "trusted" / "dummy-secret", os.O_RDONLY | os.O_NOFOLLOW)
        atomic_json(DISPATCH / "http-identity.json", {"pid": os.getpid(), "secret_fd": secret_fd,
            "identity": status, "dumpable_set_after_exec": True})
        server.handle_request()


if __name__ == "__main__":
    main()
