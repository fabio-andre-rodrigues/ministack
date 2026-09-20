"""minicorn: a minimal ASGI server for MiniStack. asyncio + stdlib only,
no hypercorn, no h11, no wsproto.

Correctness rules this encodes, each one a bug the first spike had:
  * ASGI `path` is percent-decoded, `raw_path` keeps the original bytes.
  * The query string is split at the first `?` only and never decoded.
  * 204/304 and HEAD carry no body and no Content-Length.
  * The request body is drained before a connection is reused, because an ASGI
    app is free never to call receive().
  * Keep-alive follows the version: on for 1.1 unless `Connection: close`,
    off for 1.0 unless `Connection: keep-alive`.
"""
import asyncio
import base64
import hashlib
import logging
import struct
from urllib.parse import unquote

logger = logging.getLogger("minicorn")
MAX_HEADERS = 64 * 1024
BODYLESS = frozenset((204, 304))
_REASONS = {200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
            409: "Conflict", 412: "Precondition Failed", 416: "Range Not Satisfiable",
            500: "Internal Server Error", 501: "Not Implemented", 503: "Service Unavailable"}


class _Closed(Exception):
    pass


class Connection:
    def __init__(self, app, reader, writer, scheme, initial=b""):
        self.app, self.r, self.w, self.scheme = app, reader, writer, scheme
        self._buf = bytearray(initial)

    async def _fill(self):
        data = await self.r.read(65536)
        if not data:
            raise _Closed
        self._buf += data

    async def _read_head(self):
        while b"\r\n\r\n" not in self._buf:
            if len(self._buf) > MAX_HEADERS:
                raise _Closed
            await self._fill()
        head, _, rest = bytes(self._buf).partition(b"\r\n\r\n")
        self._buf = bytearray(rest)
        return head

    async def _read_exactly(self, n):
        while len(self._buf) < n:
            await self._fill()
        out, self._buf = bytes(self._buf[:n]), bytearray(self._buf[n:])
        return out

    async def _read_line(self):
        while b"\r\n" not in self._buf:
            await self._fill()
        line, _, rest = bytes(self._buf).partition(b"\r\n")
        self._buf = bytearray(rest)
        return line + b"\r\n"

    async def serve(self):
        while True:
            try:
                head = await self._read_head()
            except _Closed:
                return
            try:
                keep = await self._one(head)
            except _Closed:
                return
            if not keep:
                return

    async def _one(self, head):
        lines = head.split(b"\r\n")
        try:
            method, target, version = lines[0].split(b" ", 2)
        except ValueError:
            await self._bare(400)
            raise _Closed
        headers = []
        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if not sep:
                await self._bare(400)
                raise _Closed
            headers.append((name.strip().lower(), value.strip()))
        lookup = dict(headers)
        raw_path, _, query = target.partition(b"?")
        http_11 = version == b"HTTP/1.1"
        conn_hdr = lookup.get(b"connection", b"").lower()
        keep = (b"close" not in conn_hdr) if http_11 else (b"keep-alive" in conn_hdr)

        body_len, chunked = 0, False
        if lookup.get(b"transfer-encoding", b"").lower().find(b"chunked") != -1:
            chunked = True
        else:
            try:
                body_len = int(lookup.get(b"content-length", b"0") or 0)
            except ValueError:
                await self._bare(400)
                raise _Closed

        if (b"upgrade" in conn_hdr
                and lookup.get(b"upgrade", b"").lower() == b"websocket"):
            await self._websocket(method, raw_path, query, headers, lookup)
            raise _Closed

        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1" if http_11 else "1.0",
            "method": method.decode("latin-1"),
            "scheme": self.scheme,
            "path": unquote(raw_path.decode("latin-1")),
            "raw_path": raw_path,
            "query_string": query,
            "root_path": "",
            "headers": headers,
            "client": self.w.get_extra_info("peername"),
            "server": self.w.get_extra_info("sockname"),
        }

        sent_expect = lookup.get(b"expect", b"").lower() == b"100-continue"
        state = {"started": False, "done": False, "drained": False, "expect": sent_expect}

        async def receive():
            if state["expect"]:
                state["expect"] = False
                self.w.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            if state["done"]:
                # The body is finished, so this is a disconnect probe: a streamed
                # response (StartLiveTail) calls receive() to learn when the client
                # goes away. Returning immediately ends the stream at once, which
                # is why it must wait for a real disconnect. Polling at_eof costs
                # nothing off the socket, so a pipelined request is never eaten.
                while not (self.r.at_eof() and not self._buf or self.w.transport is None
                           or self.w.transport.is_closing()):
                    await asyncio.sleep(0.05)
                return {"type": "http.disconnect"}
            if chunked:
                chunk = await self._read_chunk()
                if chunk is None:
                    state["done"] = True
                    return {"type": "http.request", "body": b"", "more_body": False}
                return {"type": "http.request", "body": chunk, "more_body": True}
            state["done"] = True
            body = b""
            if body_len:
                try:
                    body = await self._read_exactly(body_len)
                except _Closed:
                    raise
            return {"type": "http.request", "body": body, "more_body": False}

        bodyless = method == b"HEAD"

        async def send(message):
            t = message["type"]
            if t == "http.response.start":
                status = message["status"]
                out = [b"HTTP/1.1 %d %s\r\n" % (status, _REASONS.get(status, "").encode())]
                drop_len = status in BODYLESS
                has_len = False
                for k, v in message.get("headers", []):
                    if not isinstance(k, bytes):
                        k, v = str(k).encode(), str(v).encode()
                    lk = k.lower()
                    if lk == b"content-length":
                        if drop_len:
                            continue
                        has_len = True
                    if lk in (b"connection", b"transfer-encoding"):
                        continue
                    out.append(b"%s: %s\r\n" % (k, v))
                state["has_len"] = has_len
                state["bodyless"] = drop_len or bodyless
                out.append(b"Connection: %s\r\n" % (b"keep-alive" if keep else b"close"))
                state["head"] = b"".join(out)
                state["started"] = True
            elif t == "http.response.body":
                chunk = message.get("body", b"") or b""
                more = message.get("more_body", False)
                if state["started"]:
                    head = state.pop("head")
                    if state["bodyless"]:
                        chunk = b""
                        self.w.write(head + b"\r\n")
                    elif not more and not state["has_len"]:
                        self.w.write(head + b"Content-Length: %d\r\n\r\n" % len(chunk))
                    else:
                        if not state["has_len"]:
                            state["te_chunked"] = True
                            self.w.write(head + b"Transfer-Encoding: chunked\r\n\r\n")
                        else:
                            self.w.write(head + b"\r\n")
                    state["started"] = False
                if chunk or (not more and state.get("te_chunked")):
                    if state.get("te_chunked"):
                        if chunk:
                            self.w.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                        if not more:
                            self.w.write(b"0\r\n\r\n")
                    elif not state["bodyless"]:
                        self.w.write(chunk)
                elif chunk and not state["bodyless"]:
                    self.w.write(chunk)
                # Drain every chunk, not just the last: a streamed response
                # (CloudWatch Logs StartLiveTail, Lambda response streaming)
                # must reach the client as it is produced.
                await self.w.drain()

        try:
            # One Task per request, so each gets its own contextvar context. On a
            # keep-alive connection a shared Task would let one request's
            # contextvars (Lambda's durable execution context, the request's
            # account/region scope) leak into the next one on the same socket.
            await asyncio.ensure_future(self.app(scope, receive, send))
        except Exception:
            logger.exception("app raised for %s %s", scope["method"], scope["path"])
            raise
        # An app may never call receive(); the body must still leave the socket.
        if not state["done"]:
            if chunked:
                while await self._read_chunk() is not None:
                    pass
            elif body_len:
                try:
                    await self._read_exactly(body_len)
                except _Closed:
                    raise
        return keep


    # ---- WebSocket (RFC 6455): handshake and framing, no wsproto ------------
    _GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    async def _websocket(self, method, raw_path, query, headers, lookup):
        key = lookup.get(b"sec-websocket-key", b"")
        if method != b"GET" or not key:
            await self._bare(400)
            return
        protos = [p.strip().decode("latin-1")
                  for p in lookup.get(b"sec-websocket-protocol", b"").split(b",") if p.strip()]
        scope = {
            "type": "websocket", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "scheme": "wss" if self.scheme == "https" else "ws",
            "path": unquote(raw_path.decode("latin-1")),
            "raw_path": raw_path, "query_string": query, "root_path": "",
            "headers": headers, "subprotocols": protos,
            "client": self.w.get_extra_info("peername"),
            "server": self.w.get_extra_info("sockname"),
        }
        events = asyncio.Queue()
        await events.put({"type": "websocket.connect"})
        state = {"accepted": False, "closed": False, "reader": None}

        async def receive():
            return await events.get()

        async def send(message):
            t = message["type"]
            if t == "websocket.accept":
                if state["accepted"]:
                    return
                accept = base64.b64encode(hashlib.sha1(key + self._GUID).digest())
                out = [b"HTTP/1.1 101 Switching Protocols\r\n",
                       b"Upgrade: websocket\r\n", b"Connection: Upgrade\r\n",
                       b"Sec-WebSocket-Accept: " + accept + b"\r\n"]
                sub = message.get("subprotocol")
                if sub:
                    out.append(b"Sec-WebSocket-Protocol: " + str(sub).encode("latin-1") + b"\r\n")
                for k, v in message.get("headers", []) or []:
                    out.append(b"%s: %s\r\n" % (k, v))
                out.append(b"\r\n")
                self.w.write(b"".join(out))
                await self.w.drain()
                state["accepted"] = True
                state["reader"] = asyncio.create_task(self._ws_read_loop(events, state))
            elif t == "websocket.send":
                if not state["accepted"] or state["closed"]:
                    return
                data = message.get("bytes")
                if data is None:
                    text = message.get("text") or ""
                    self._ws_write(0x1, text.encode("utf-8"))
                else:
                    self._ws_write(0x2, data)
                await self.w.drain()
            elif t == "websocket.close":
                if state["closed"]:
                    return
                state["closed"] = True
                if state["accepted"]:
                    code = int(message.get("code", 1000))
                    self._ws_write(0x8, struct.pack("!H", code))
                    try:
                        await self.w.drain()
                    except Exception:
                        pass
                else:
                    # Rejected before the handshake: HTTP, not a close frame.
                    self.w.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
                    try:
                        await self.w.drain()
                    except Exception:
                        pass

        try:
            await self.app(scope, receive, send)
        finally:
            task = state.get("reader")
            if task is not None:
                task.cancel()

    def _ws_write(self, opcode, payload):
        n = len(payload)
        if n < 126:
            head = struct.pack("!BB", 0x80 | opcode, n)
        elif n < 65536:
            head = struct.pack("!BBH", 0x80 | opcode, 126, n)
        else:
            head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
        self.w.write(head + payload)

    async def _ws_read_loop(self, events, state):
        """Feed websocket.receive / websocket.disconnect from the wire."""
        frag, frag_op = bytearray(), None
        try:
            while not state["closed"]:
                b1, b2 = await self._read_exactly(2)
                fin, opcode = b1 & 0x80, b1 & 0x0F
                masked, length = b2 & 0x80, b2 & 0x7F
                if length == 126:
                    (length,) = struct.unpack("!H", await self._read_exactly(2))
                elif length == 127:
                    (length,) = struct.unpack("!Q", await self._read_exactly(8))
                mask = await self._read_exactly(4) if masked else b""
                data = await self._read_exactly(length) if length else b""
                if masked:
                    data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                if opcode == 0x8:
                    state["closed"] = True
                    self._ws_write(0x8, data[:2] or struct.pack("!H", 1000))
                    await self.w.drain()
                    await events.put({"type": "websocket.disconnect", "code": 1000})
                    return
                if opcode == 0x9:
                    self._ws_write(0xA, data)
                    await self.w.drain()
                    continue
                if opcode == 0xA:
                    continue
                if opcode == 0x0:
                    frag += data
                else:
                    frag, frag_op = bytearray(data), opcode
                if not fin:
                    continue
                payload, op = bytes(frag), frag_op
                frag, frag_op = bytearray(), None
                if op == 0x1:
                    await events.put({"type": "websocket.receive",
                                      "text": payload.decode("utf-8", errors="replace")})
                else:
                    await events.put({"type": "websocket.receive", "bytes": payload})
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            if not state["closed"]:
                state["closed"] = True
                await events.put({"type": "websocket.disconnect", "code": 1006})

    async def _read_chunk(self):
        line = await self._read_line()
        if not line:
            raise _Closed
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            raise _Closed
        if size == 0:
            await self._read_line()
            return None
        data = await self._read_exactly(size)
        await self._read_exactly(2)
        return data

    async def _bare(self, status):
        self.w.write(b"HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                     % (status, _REASONS.get(status, "").encode()))
        try:
            await self.w.drain()
        except Exception:
            pass



# ---- HTTP/2 -----------------------------------------------------------------
# `h2` is imported only when an HTTP/2 client actually appears: prior-knowledge
# cleartext (the connection preface) or an `Upgrade: h2c` request. Everyone else
# never pays for h2/hpack/hyperframe.
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


async def _serve_h2(app, reader, writer, scheme, preface_consumed=b""):
    import h2.config
    import h2.connection
    import h2.events

    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=False, header_encoding=None))
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()
    streams = {}

    async def pump():
        while True:
            data = await reader.read(65536)
            if not data:
                return
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    streams[event.stream_id] = asyncio.Queue()
                    asyncio.ensure_future(
                        _h2_request(app, conn, writer, scheme, event, streams))
                elif isinstance(event, h2.events.DataReceived):
                    q = streams.get(event.stream_id)
                    if q is not None:
                        q.put_nowait((event.data, False))
                    conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    q = streams.get(event.stream_id)
                    if q is not None:
                        q.put_nowait((b"", True))
                elif isinstance(event, (h2.events.ConnectionTerminated,)):
                    return
            out = conn.data_to_send()
            if out:
                writer.write(out)
                await writer.drain()

    await pump()


async def _h2_request(app, conn, writer, scheme, event, streams):
    headers = [(k.lower(), v) for k, v in event.headers
               if not k.startswith(b":")]
    pseudo = {k: v for k, v in event.headers if k.startswith(b":")}
    target = pseudo.get(b":path", b"/")
    raw_path, _, query = target.partition(b"?")
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "2", "method": pseudo.get(b":method", b"GET").decode("latin-1"),
        "scheme": pseudo.get(b":scheme", scheme.encode()).decode("latin-1"),
        "path": unquote(raw_path.decode("latin-1")), "raw_path": raw_path,
        "query_string": query, "root_path": "", "headers": headers,
        "client": writer.get_extra_info("peername"), "server": writer.get_extra_info("sockname"),
    }
    q = streams[event.stream_id]
    ended = {"v": event.stream_ended is not None}

    async def receive():
        if ended["v"] and q.empty():
            return {"type": "http.disconnect"}
        body, last = await q.get()
        if last:
            ended["v"] = True
        return {"type": "http.request", "body": body, "more_body": not last}

    started = {"v": False}

    async def send(message):
        if message["type"] == "http.response.start":
            out = [(b":status", str(message["status"]).encode())]
            for k, v in message.get("headers", []):
                lk = k.lower()
                if lk in (b"connection", b"transfer-encoding", b"keep-alive"):
                    continue
                out.append((lk, v))
            conn.send_headers(event.stream_id, out)
            started["v"] = True
        elif message["type"] == "http.response.body":
            data = message.get("body", b"") or b""
            more = message.get("more_body", False)
            closed = False
            while data:
                allowed = conn.local_flow_control_window(event.stream_id)
                if allowed <= 0:
                    await asyncio.sleep(0.01)
                    continue
                chunk, data = data[:allowed], data[allowed:]
                last = not more and not data
                conn.send_data(event.stream_id, chunk, end_stream=last)
                closed = closed or last
                writer.write(conn.data_to_send())
                await writer.drain()
            # Only close once: send_data already carried END_STREAM when it could.
            if not more and not closed:
                try:
                    conn.end_stream(event.stream_id)
                except Exception:
                    pass
        out = conn.data_to_send()
        if out:
            writer.write(out)
            await writer.drain()

    try:
        await asyncio.ensure_future(app(scope, receive, send))
    except Exception:
        logger.exception("h2 app raised")
    finally:
        streams.pop(event.stream_id, None)

async def serve(app, host="0.0.0.0", port=4566, scheme="http", ssl_context=None):
    async def handler(reader, writer):
        try:
            first = b""
            while len(first) < len(H2_PREFACE):
                chunk = await reader.read(len(H2_PREFACE) - len(first))
                if not chunk:
                    break
                first += chunk
                if not H2_PREFACE.startswith(first):
                    break            # definitely not HTTP/2, stop sniffing
            if first == H2_PREFACE:
                await _serve_h2(app, reader, writer, scheme)
                return
            await Connection(app, reader, writer, scheme, initial=first).serve()
        except Exception:
            logger.exception("connection failed")
        finally:
            try:
                writer.close()
            except Exception:
                pass
    server = await asyncio.start_server(handler, host, port, ssl=ssl_context, limit=1024 * 1024)
    async with server:
        await server.serve_forever()
