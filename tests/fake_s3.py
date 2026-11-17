"""Minimal in-memory S3 (path-style) that VERIFIES AWS SigV4 signatures: PUT / GET / DELETE / ListObjectsV2."""
import hashlib
import hmac
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "agents", "linux"))
from helpers import free_port  # noqa: E402


def _hmac(k, m):
    return hmac.new(k, m.encode(), hashlib.sha256).digest()


class FakeS3:
    def __init__(self, access_key="AKTEST", secret_key="secret-test-key", bucket="backups", host="127.0.0.1"):
        self.ak, self.sk, self.bucket = access_key, secret_key, bucket
        self.objects = {}
        self.bad_signatures = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _verify(self, body_hash):
                auth = self.headers.get("Authorization", "")
                try:
                    cred = auth.split("Credential=")[1].split(",")[0]
                    signed = auth.split("SignedHeaders=")[1].split(",")[0]
                    sig = auth.split("Signature=")[1].strip()
                    ak, date, region, svc, term = cred.split("/")
                except (IndexError, ValueError):
                    return False
                u = urllib.parse.urlsplit(self.path)
                q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
                cq = "&".join("%s=%s" % (urllib.parse.quote(k, safe="-_.~"), urllib.parse.quote(v, safe="-_.~")) for k, v in sorted(q))
                names = signed.split(";")
                ch = "".join("%s:%s\n" % (n, " ".join((self.headers.get(n) or "").split())) for n in names)
                canon = "\n".join([self.command, u.path, cq, ch, signed, self.headers.get("x-amz-content-sha256", "")])
                scope = "/".join([date, region, svc, term])
                sts = "\n".join(["AWS4-HMAC-SHA256", self.headers.get("x-amz-date", ""), scope, hashlib.sha256(canon.encode()).hexdigest()])
                k = _hmac(_hmac(_hmac(_hmac(("AWS4" + outer.sk).encode(), date), region), svc), term)
                ok = ak == outer.ak and hmac.compare_digest(hmac.new(k, sts.encode(), hashlib.sha256).hexdigest(), sig)
                if ok and body_hash is not None and self.headers.get("x-amz-content-sha256") not in (body_hash, "UNSIGNED-PAYLOAD"):
                    ok = False
                if not ok:
                    outer.bad_signatures += 1
                return ok

            def _key(self):
                path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
                parts = path.lstrip("/").split("/", 1)
                return parts[0], (parts[1] if len(parts) > 1 else "")

            def _reply(self, code, body=b"", ctype="application/xml"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PUT(self):
                n = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(n)
                if not self._verify(hashlib.sha256(data).hexdigest()):
                    return self._reply(403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>")
                b, k = self._key()
                outer.objects[k] = data
                self._reply(200)

            def do_GET(self):
                if not self._verify(None):
                    return self._reply(403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>")
                b, k = self._key()
                q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
                if not k and q.get("list-type") == "2":
                    pre = q.get("prefix", "")
                    items = "".join("<Contents><Key>%s</Key><Size>%d</Size></Contents>" % (escape(kk), len(v))
                                    for kk, v in sorted(outer.objects.items()) if kk.startswith(pre))
                    body = ('<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                            "<Name>%s</Name><IsTruncated>false</IsTruncated>%s</ListBucketResult>" % (b, items)).encode()
                    return self._reply(200, body)
                if k not in outer.objects:
                    return self._reply(404, b"<Error><Code>NoSuchKey</Code></Error>")
                self._reply(200, outer.objects[k], "application/octet-stream")

            def do_DELETE(self):
                if not self._verify(None):
                    return self._reply(403)
                outer.objects.pop(self._key()[1], None)
                self._reply(204)

        class Quiet(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass          # clients closing keep-alive connections abruptly is normal

        self.port = free_port()
        self.srv = Quiet((host, self.port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.endpoint = "http://%s:%d" % (host, self.port)

    def stop(self):
        self.srv.shutdown()
