#!/usr/bin/env python3
"""meshcore-web - the admin page of a MeshCore hotspot or repeater.

Plain HTTP on the LAN, user 'admin' with the config's web_password (no password
set = the page stays off). It never touches the radio itself:

  - status, commands and the live monitor go over the repeater's control port
    (127.0.0.1, one command per connection; 'monitor' keeps streaming);
  - settings are edited in the config file in place, keeping its comments, then
    applied with 'reload' or, for the keys that need it, a service restart
    ('quit': systemd brings the repeater back in a few seconds).

Standard library only. Runs as the 'meshcore' user, see meshcore-web.service.
"""
import base64
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CONF = os.environ.get("MESHCORE_CONF", "/opt/meshcore-repeater/meshcore-repeater.conf")
HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index.html")
SERVICE = "meshcore-repeater"

# Repeatable keys: one line per entry in the config file.
LIST_KEYS = {"public_channel", "room", "blacklist", "affinity", "home", "probe_allow"}

# Every single-valued key the repeater knows (config.c). Their values are read
# back from the running repeater ('get'), so defaults show too.
SCALAR_KEYS = (
    "name role location latitude longitude advert_interval forward "
    "frequency bandwidth spreading_factor coding_rate tx_power preamble sync_word crc "
    "iq_inverted use_cad tcxo_voltage ocp "
    "hotspot_power_high hotspot_power_low hotspot_awake "
    "ping_pong ping_channel timeofday mbox "
    "backbone backbone_host backbone_port backbone_hub_key backbone_observe backbone_bridge "
    "backbone_rate backbone_policy backbone_policy_file "
    "aprs_enable aprs_call aprs_passcode aprs_host aprs_port aprs_tocall aprs_symbol "
    "aprs_node_symbol aprs_comment aprs_altitude aprs_beacon_interval aprs_node_rate "
    "spi_dev spi_speed gpio_chip gpio_reset gpio_busy gpio_dio1 gpio_nss rf_switch "
    "gpio_rxen gpio_txen use_leds gpio_led_on gpio_led_data "
    "control_port key_file link_mode link_peer link_port web_port"
).split()

# Keys the running repeater only picks up on a restart ('reload' is not enough).
RESTART_KEYS = {
    "name", "sync_word", "crc", "iq_inverted", "tcxo_voltage", "ocp",
    "spi_dev", "spi_speed", "gpio_chip", "gpio_reset", "gpio_busy", "gpio_dio1",
    "gpio_nss", "rf_switch", "gpio_rxen", "gpio_txen", "use_leds", "gpio_led_on",
    "gpio_led_data", "key_file", "control_port", "link_mode", "link_peer", "link_port",
    "link_key", "backbone", "backbone_host", "backbone_port", "backbone_hub_key",
    "backbone_observe", "backbone_bridge", "backbone_rate", "backbone_policy",
    "backbone_policy_file", "aprs_enable", "aprs_call", "aprs_passcode", "aprs_host",
    "aprs_port", "aprs_tocall", "aprs_symbol", "aprs_node_symbol", "aprs_comment",
    "aprs_altitude", "aprs_beacon_interval", "aprs_node_rate",
}
WEB_KEYS = {"web_port", "web_password"}       # this service restarts itself for these
SECRET_KEYS = {"web_password", "link_key"}   # never shown; a blank field leaves them as they are

KEY_RE = re.compile(r"^[a-z0-9_]{1,40}$")
TARGET_RE = re.compile(r"^#?[A-Za-z0-9_-]{1,31}$")
_conf_lock = threading.Lock()


# ---- config file ----------------------------------------------------------

def _active(line):
    """(key, value) of an active 'key = value' line, as the repeater reads it:
    '#' starts a comment anywhere, so a value never holds one."""
    s = line.split("#", 1)[0].strip()
    if "=" not in s:
        return None
    k, v = s.split("=", 1)
    k, v = k.strip(), v.strip()
    return (k, v) if k else None


def read_conf():
    vals, lists = {}, {k: [] for k in LIST_KEYS}
    with open(CONF, encoding="utf-8", errors="replace") as f:
        for line in f:
            kv = _active(line)
            if not kv:
                continue
            k, v = kv
            if k in LIST_KEYS:
                lists[k].append(v)
            else:
                vals[k] = v
    return vals, lists


def conf_value(key):
    vals, _ = read_conf()
    return vals.get(key, "")


def _fmt(key, value, comment=""):
    line = "%-18s = %s" % (key, value)
    return line + ("    " + comment if comment else "")


def write_conf(changes):
    """Rewrite the config with `changes` ({key: str | [str]}), in place: the first
    active line of a key is replaced (keeping its trailing comment), later lines
    of the same key are dropped, and new keys are appended at the end."""
    with _conf_lock:
        with open(CONF, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        out, done = [], set()
        for line in lines:
            kv = _active(line)
            if kv and kv[0] in changes:
                k = kv[0]
                if k in done:
                    continue
                done.add(k)
                v = changes[k]
                comment = line[line.index("#"):] if "#" in line else ""
                if isinstance(v, list):
                    out.extend(_fmt(k, x) for x in v)
                else:
                    out.append(_fmt(k, v, comment))
                continue
            out.append(line)
        added = [k for k in changes if k not in done]
        if added:
            out.append("")
            out.append("# ---- set from the web admin page ----")
        for k in added:
            v = changes[k]
            out.extend(_fmt(k, x) for x in v) if isinstance(v, list) else out.append(_fmt(k, v))
        tmp = CONF + ".web.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, CONF)


def _clean_value(key, v):
    v = str(v).strip()
    if "#" in v and key not in ("room", "ping_channel"):
        raise ValueError("%s: a value can't contain '#' (it starts a comment)" % key)
    if "\n" in v or "\r" in v:
        raise ValueError("%s: one line only" % key)
    if key in ("room", "ping_channel"):
        v = v.lstrip("#")              # stored bare: the repeater adds the '#'
    return v


# ---- the repeater's control port --------------------------------------------

def control_port():
    try:
        return int(conf_value("control_port") or 4403)
    except ValueError:
        return 4403


def ctl(cmd, timeout=5.0):
    """Run one CLI command on the repeater and return its output."""
    with socket.create_connection(("127.0.0.1", control_port()), timeout=timeout) as s:
        s.sendall((cmd + "\n").encode())
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks).decode("utf-8", "replace")


def ctl_get(key):
    out = ctl("get " + key).strip()
    return out.split(" = ", 1)[1] if " = " in out else ""


def parse_status(txt):
    rows = []
    for line in txt.splitlines():
        if " : " in line or line.rstrip().endswith(":"):
            k, _, v = line.partition(":")
            rows.append([k.strip(), v.strip()])
    return rows


def parse_neighbors(txt):
    rows = []
    for line in txt.splitlines()[1:]:
        p = line.split()
        if len(p) < 7 or not re.fullmatch(r"[0-9a-f]{12}", p[0]):
            continue
        try:
            rows.append({"id": p[0], "name": " ".join(p[1:-5]), "type": p[-5],
                         "hops": int(p[-4]), "rssi": int(p[-3]), "snr": float(p[-2]),
                         "age": int(p[-1])})
        except ValueError:
            continue
    return rows


def parse_channels(txt):
    rows = []
    for line in txt.splitlines():
        m = re.match(r"\s*\[(\d+)\] hash 0x([0-9A-F]{2})\s+(\d+)-bit\s+(.*?)(\s+\(hub room\))?\s*$", line)
        if m:
            rows.append({"hash": m.group(2), "bits": int(m.group(3)),
                         "name": m.group(4), "hub": bool(m.group(5))})
    return rows


def parse_blacklist(txt):
    local, hub, cur = [], [], None
    for line in txt.splitlines():
        if line.startswith("blacklist ("):
            cur = local
        elif line.startswith("blocked by the hub"):
            cur = hub
        elif line.startswith("  ") and cur is not None and line.strip() != "(empty)":
            cur.append(line.strip())
    return local, hub


# ---- HTTP -------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "meshcore-web"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):         # quiet: no per-request journal lines
        pass

    # -- helpers --
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        password = conf_value("web_password")
        hdr = self.headers.get("Authorization", "")
        if password and hdr.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(hdr[6:]).decode("utf-8").partition(":")
            except (ValueError, UnicodeDecodeError):
                user, pw = "", ""
            if hmac.compare_digest(user.encode(), b"admin") and \
               hmac.compare_digest(pw.encode(), password.encode()):
                return True
        time.sleep(1)                           # slow down guessing
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="MeshCore admin", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _json_body(self):
        # A cross-site page can't send a custom header or a JSON content type
        # without a CORS preflight, which this server never answers.
        if self.headers.get("X-MeshCore") != "1" or \
           not self.headers.get("Content-Type", "").startswith("application/json"):
            raise PermissionError("missing X-MeshCore header")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def _sse_start(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _sse(self, line):
        self.wfile.write(b"data: " + line.replace(b"\r", b"") + b"\n\n")
        self.wfile.flush()

    # -- routes --
    def do_GET(self):
        if not self._authorized():
            return
        u = urlparse(self.path)
        try:
            if u.path == "/":
                with open(INDEX, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if u.path == "/api/overview":
                return self._send(200, self.overview())
            if u.path == "/api/config":
                return self._send(200, self.config())
            if u.path == "/api/monitor":
                return self.monitor(parse_qs(u.query).get("target", ["all"])[0])
            if u.path == "/api/journal":
                return self.journal()
            return self._send(404, {"error": "not found"})
        except (ConnectionError, socket.timeout, OSError) as e:
            if isinstance(e, (BrokenPipeError, ConnectionResetError)):
                return
            return self._send(503, {"error": "the repeater isn't answering (%s)" % e})

    def do_POST(self):
        if not self._authorized():
            return
        u = urlparse(self.path)
        try:
            body = self._json_body()
            if u.path == "/api/cli":
                return self.cli(body)
            if u.path == "/api/config":
                return self.save_config(body)
            if u.path == "/api/action":
                return self.action(body)
            return self._send(404, {"error": "not found"})
        except PermissionError as e:
            return self._send(403, {"error": str(e)})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except (ConnectionError, socket.timeout, OSError) as e:
            return self._send(503, {"error": "the repeater isn't answering (%s)" % e})

    # -- API --
    def overview(self):
        local, hub = parse_blacklist(ctl("blacklist list"))
        return {
            "status": parse_status(ctl("status")),
            "neighbors": parse_neighbors(ctl("neighbors")),
            "channels": parse_channels(ctl("channels")),
            "blacklist": local, "hub_blocks": hub,
            "hostname": socket.gethostname(),
        }

    def config(self):
        _, lists = read_conf()
        values = {k: ctl_get(k) for k in SCALAR_KEYS}
        values["link_key"] = values["web_password"] = ""       # never sent out
        return {"values": values, "lists": lists, "restart_keys": sorted(RESTART_KEYS),
                "secret_set": {k: bool(conf_value(k)) for k in ("link_key", "web_password")}}

    def save_config(self, body):
        changes = {}
        for k, v in (body.get("values") or {}).items():
            if not KEY_RE.match(k) or k in LIST_KEYS:
                raise ValueError("bad key %r" % k)
            if k in SECRET_KEYS and v == "":
                continue                         # left blank = unchanged
            changes[k] = _clean_value(k, v)
        for k, v in (body.get("lists") or {}).items():
            if k not in LIST_KEYS or not isinstance(v, list):
                raise ValueError("bad list %r" % k)
            changes[k] = [_clean_value(k, x) for x in v if str(x).strip()]
        if not changes:
            return self._send(200, {"applied": "nothing changed"})
        write_conf(changes)
        if any(k in RESTART_KEYS for k in changes):
            ctl("quit")                          # systemd restarts it (RestartSec=5)
            applied = "restart"
        elif set(changes) - WEB_KEYS:
            out = ctl("reload")
            applied = "reload: " + out.strip()
        else:
            applied = "saved"
        self._send(200, {"applied": applied, "changed": sorted(changes)})
        if set(changes) & WEB_KEYS:              # new port/password: systemd starts us over
            threading.Timer(0.5, lambda: os._exit(75)).start()

    def cli(self, body):
        line = str(body.get("line", "")).strip()
        if not line or "\n" in line or len(line) > 400:
            raise ValueError("one command line, please")
        if line.split()[0].lower() == "monitor":
            raise ValueError("use the Live log tab for 'monitor'")
        return self._send(200, {"output": ctl(line, timeout=8.0)})

    def action(self, body):
        a = body.get("action")
        if a == "advert":
            out = ctl("advert")
        elif a == "reload":
            out = ctl("reload")
        elif a == "restart":
            ctl("quit")
            out = "restarting - back in a few seconds"
        elif a == "probe":
            secs, count = int(body.get("secs", 0)), int(body.get("count", 0))
            out = ctl("probe %d %d" % (secs, count))
        elif a in ("blacklist_add", "blacklist_remove"):
            name = _clean_value("blacklist", body.get("name", ""))
            if not name:
                raise ValueError("name required")
            _, lists = read_conf()
            bl = [x for x in lists["blacklist"] if x.lower() != name.lower()]
            if a == "blacklist_add":
                bl.append(name)
            write_conf({"blacklist": bl})
            out = ctl("reload")
        else:
            raise ValueError("unknown action")
        return self._send(200, {"output": out})

    def monitor(self, target):
        if not TARGET_RE.match(target):
            return self._send(400, {"error": "bad monitor target"})
        s = socket.create_connection(("127.0.0.1", control_port()), timeout=5)
        try:
            s.sendall(("monitor %s\n" % target).encode())
            s.settimeout(15)
            self._sse_start()
            buf = b""
            while True:
                try:
                    b = s.recv(4096)
                except socket.timeout:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if not b:
                    self._sse(b"# the repeater closed the monitor (restarting?)")
                    break
                buf += b
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._sse(line)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            s.close()

    def journal(self):
        try:
            p = subprocess.Popen(["journalctl", "-u", SERVICE, "-f", "-n", "200",
                                  "-o", "short", "--no-pager"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except OSError as e:
            return self._send(503, {"error": "journalctl: %s" % e})
        self._sse_start()
        try:
            for line in p.stdout:
                self._sse(line.rstrip(b"\n"))
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            p.kill()
            p.wait()


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, socket.timeout)):
            return                              # a browser closed the tab mid-stream
        super().handle_error(request, client_address)


def main():
    try:
        password = conf_value("web_password")
        port = int(conf_value("web_port") or 80)
    except OSError as e:
        print("meshcore-web: can't read %s: %s" % (CONF, e), file=sys.stderr)
        return 1
    if not password or port == 0:
        print("meshcore-web: off (set web_password in %s to turn the admin page on)" % CONF)
        return 0
    srv = Server(("0.0.0.0", port), Handler)
    print("meshcore-web: admin page on http://%s:%d/ (user admin)" % (socket.gethostname(), port))
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
