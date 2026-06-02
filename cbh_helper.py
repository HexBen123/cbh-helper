from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import html
import io
import json
import logging
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import uuid
import webbrowser
import zipfile
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    PartialAuthentication,
)


APP_NAME = "CBH Helper"
APP_VERSION = "0.1.0"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC_RE = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")
ANSI_SIMPLE_RE = re.compile(r"\x1b[@-Z\\-_]")
NON_TEXT_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def bundled_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent


def writable_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


BUNDLE_DIR = bundled_base_dir()
APP_DIR = writable_base_dir()
CONFIG_PATH = APP_DIR / "cbh-helper.json"


DEFAULT_CONFIG: dict[str, Any] = {
    "bastion_host": "",
    "bastion_port": 0,
    "bastion_username": "",
    "target_command": "",
    "default_resource_account": "",
    "target_profiles": [],
    "credential_cache_ttl_seconds": 0,
    "mcp_exec_timeout_seconds": 300,
    "mcp_exec_ready_timeout_seconds": 60,
    "mcp_exec_append_exit_code": False,
    "mcp_exec_strip_terminal_controls": True,
    "mcp_exec_serialize_login": True,
    "mcp_exec_login_lock_timeout_seconds": 120,
    "ssh_keepalive_seconds": 30,
    "websocket_keepalive_seconds": 30,
    "web_terminal_shell_keepalive_seconds": 60,
    "local_ssh_suppress_cached_login_prelude": True,
    "jump_delay_seconds": 1.0,
    "connect_timeout_seconds": 15.0,
    "web_host": "127.0.0.1",
    "web_port": 8088,
    "open_browser_on_start": True,
    "local_ssh_host": "127.0.0.1",
    "local_ssh_port": 10022,
    "local_host_key_path": "cbh-local-hostkey.key",
}


@dataclass
class CredentialBundle:
    username: str
    password: str
    mfa_code: str
    target_command: str
    resource_account: str
    resource_password: str
    expires_at: float

    @property
    def remaining_seconds(self) -> int:
        if self.expires_at == float("inf"):
            return -1
        return max(0, int(self.expires_at - time.time()))


class CredentialCache:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.bundle: CredentialBundle | None = None

    def set(
        self,
        username: str,
        password: str,
        mfa_code: str,
        target_command: str,
        resource_account: str,
        resource_password: str,
        ttl_seconds: int,
    ) -> None:
        with self.lock:
            self.bundle = CredentialBundle(
                username=username,
                password=password,
                mfa_code=mfa_code,
                target_command=target_command,
                resource_account=resource_account,
                resource_password=resource_password,
                expires_at=float("inf") if ttl_seconds <= 0 else time.time() + max(60, ttl_seconds),
            )

    def get(self) -> CredentialBundle | None:
        with self.lock:
            if self.bundle is None:
                return None
            if self.bundle.expires_at <= time.time():
                self.bundle = None
                return None
            return self.bundle


CREDENTIAL_CACHE = CredentialCache()
MCP_EXEC_LOGIN_LOCK = threading.Lock()


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            user_config = json.load(f)
        config.update(user_config)
    discovered = discover_login_config()
    if not config.get("bastion_host") and discovered.get("bastion_host"):
        config["bastion_host"] = discovered["bastion_host"]
    if not config.get("bastion_port") and discovered.get("bastion_port"):
        config["bastion_port"] = discovered["bastion_port"]
    if not config.get("target_profiles") and discovered.get("target_profiles"):
        config["target_profiles"] = discovered["target_profiles"]
    if not config.get("target_command") and config.get("target_profiles"):
        first_profile = config["target_profiles"][0]
        if isinstance(first_profile, dict):
            config["target_command"] = first_profile.get("target_command", "")
    return config


def save_default_config(path: Path = CONFIG_PATH) -> None:
    if not path.exists():
        with path.open("w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
            f.write("\n")


def decode_config_text(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gbk"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def parse_config_port(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        if re.fullmatch(r"[0-9a-fA-F]{8}", value):
            return int(value, 16)
        return int(value)
    except ValueError:
        return None


def iter_zip_text_entries(zip_path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    try:
        with zipfile.ZipFile(zip_path) as outer:
            for entry in outer.infolist():
                if entry.is_dir():
                    continue
                data = outer.read(entry)
                if entry.filename.lower().endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(data)) as inner:
                        for inner_entry in inner.infolist():
                            if inner_entry.is_dir():
                                continue
                            if not inner_entry.filename.lower().endswith((".ini", ".xsh", ".vbs")):
                                continue
                            entries.append(
                                (
                                    inner_entry.filename,
                                    decode_config_text(inner.read(inner_entry)),
                                )
                            )
                elif entry.filename.lower().endswith((".ini", ".xsh", ".vbs")):
                    entries.append((entry.filename, decode_config_text(data)))
    except (OSError, zipfile.BadZipFile):
        return []
    return entries


def profile_name_from_command(command: str) -> str:
    command = command.strip()
    if command.startswith("?"):
        parts = command[1:].split("_")
        if len(parts) >= 2:
            return f"{parts[0]}:{parts[1]}"
    return command or "manual"


def parse_target_command(command: str) -> tuple[str, str, str] | None:
    command = command.strip()
    if not command.startswith("?"):
        return None
    parts = command[1:].split("_")
    if len(parts) < 3:
        return None
    host, port, resource_id = parts[0], parts[1], parts[2]
    if not host or not port.isdigit():
        return None
    return host, port, resource_id


def resource_info_from_entry_name(name: str) -> tuple[str, str]:
    basename = name.replace("\\", "/").rsplit("/", 1)[-1]
    if "@" not in basename:
        return "", ""
    stem = basename.rsplit(".", 1)[0]
    parts = stem.split("@")
    if len(parts) < 3:
        return "", ""
    account = parts[0].strip()
    resource_name = "@".join(parts[1:-1]).strip()
    if not account or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", account):
        account = ""
    return account, resource_name


def add_discovered_command(
    command_records: dict[str, dict[str, str]],
    command_order: list[str],
    command: str,
    account: str,
    resource_name: str,
) -> None:
    command = command.strip().strip("'").strip('"')
    account = account.strip()
    resource_name = resource_name.strip()
    if not command:
        return
    if command not in command_records:
        command_records[command] = {
            "command": command,
            "account": account,
            "resource_name": resource_name,
        }
        command_order.append(command)
    else:
        if account and not command_records[command].get("account"):
            command_records[command]["account"] = account
        if resource_name and not command_records[command].get("resource_name"):
            command_records[command]["resource_name"] = resource_name


def build_target_profiles(
    command_records: dict[str, dict[str, str]],
    command_order: list[str],
) -> list[dict[str, Any]]:
    profile_order: list[tuple[str, str]] = []
    profiles_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    fallback_profiles: list[dict[str, Any]] = []

    for command in command_order:
        record = command_records[command]
        account = record.get("account", "").strip()
        resource_name = record.get("resource_name", "").strip()
        parsed = parse_target_command(command)
        if parsed is None:
            fallback_profiles.append(
                {
                    "name": resource_name or profile_name_from_command(command),
                    "resource_name": resource_name,
                    "target_command": command,
                    "resource_account": account,
                    "accounts": [],
                }
            )
            continue

        host, port, resource_id = parsed
        key = (host, port)
        if key not in profiles_by_key:
            resource_host = f"{host}:{port}"
            profiles_by_key[key] = {
                "name": f"{resource_name} ({resource_host})" if resource_name else resource_host,
                "resource_name": resource_name,
                "resource_host": resource_host,
                "target_command": "",
                "resource_account": "",
                "accounts": [],
                "_first_command": command,
            }
            profile_order.append(key)

        profile = profiles_by_key[key]
        if resource_name and not profile.get("resource_name"):
            profile["resource_name"] = resource_name
            profile["name"] = f"{resource_name} ({profile['resource_host']})"
        if resource_id == "-1":
            profile["target_command"] = command
        elif not profile["target_command"]:
            profile["target_command"] = command

        if account:
            accounts = profile["accounts"]
            if not any(item.get("account") == account for item in accounts):
                accounts.append(
                    {
                        "account": account,
                        "target_command": command,
                        "resource_password": "",
                    }
                )

    profiles: list[dict[str, Any]] = []
    for key in profile_order:
        profile = profiles_by_key[key]
        if not profile["target_command"]:
            profile["target_command"] = profile["_first_command"]
        profile.pop("_first_command", None)
        profiles.append(profile)
    profiles.extend(fallback_profiles)
    return profiles


def discover_login_config() -> dict[str, Any]:
    search_dirs = []
    for directory in (APP_DIR, Path.cwd()):
        if directory not in search_dirs:
            search_dirs.append(directory)

    discovered: dict[str, Any] = {
        "bastion_host": "",
        "bastion_port": None,
        "target_profiles": [],
    }
    command_records: dict[str, dict[str, str]] = {}
    command_order: list[str] = []

    for directory in search_dirs:
        for zip_path in directory.glob("*AutoLoginConfig*.zip"):
            for name, text in iter_zip_text_entries(zip_path):
                resource_account, resource_name = resource_info_from_entry_name(name)
                for raw_line in text.splitlines():
                    line = raw_line.strip()
                    if line.startswith("Host=") and not discovered["bastion_host"]:
                        discovered["bastion_host"] = line.split("=", 1)[1].strip()
                    elif line.startswith('S:"Hostname"=') and not discovered["bastion_host"]:
                        discovered["bastion_host"] = line.split("=", 1)[1].strip()
                    elif line.startswith("Port=") and discovered["bastion_port"] is None:
                        discovered["bastion_port"] = parse_config_port(line.split("=", 1)[1])
                    elif line.startswith('D:"[SSH2] Port"=') and discovered["bastion_port"] is None:
                        discovered["bastion_port"] = parse_config_port(line.split("=", 1)[1])
                    elif "ExpectSend_Send_" in line and "=" in line:
                        command = line.split("=", 1)[1]
                        add_discovered_command(
                            command_records,
                            command_order,
                            command,
                            resource_account,
                            resource_name,
                        )
                    elif line.startswith('S:"Script Arguments"='):
                        command = line.split("=", 1)[1]
                        add_discovered_command(
                            command_records,
                            command_order,
                            command,
                            resource_account,
                            resource_name,
                        )
                    else:
                        match = re.search(r'Send\s+"([^"]+)"', line)
                        if match:
                            command = match.group(1)
                            add_discovered_command(
                                command_records,
                                command_order,
                                command,
                                resource_account,
                                resource_name,
                            )

    discovered["target_profiles"] = build_target_profiles(command_records, command_order)
    return discovered


def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(1.5)
            try:
                banner = sock.recv(128).decode("ascii", errors="replace").strip()
            except socket.timeout:
                banner = ""
            return True, banner
    except OSError as exc:
        return False, str(exc)


def ensure_host_key(path: Path) -> paramiko.RSAKey:
    if path.exists():
        return paramiko.RSAKey.from_private_key_file(str(path))
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(str(path))
    return key


def configure_socket_keepalive(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


def configure_transport_keepalive(
    transport: paramiko.Transport,
    config: dict[str, Any],
) -> None:
    interval = int(config.get("ssh_keepalive_seconds", 30))
    if interval > 0:
        transport.set_keepalive(interval)


def _prompt_matches(prompt: str, words: tuple[str, ...]) -> bool:
    lowered = prompt.lower()
    return any(word in lowered for word in words)


def open_bastion_shell(
    config: dict[str, Any],
    username: str,
    password: str,
    mfa_code: str = "",
    cols: int = 100,
    rows: int = 30,
    term: str = "xterm",
    target_command_override: str | None = None,
    on_status: Callable[[str], None] | None = None,
) -> tuple[paramiko.Transport, paramiko.Channel]:
    def status(message: str) -> None:
        if on_status:
            on_status(message)

    host = str(config["bastion_host"])
    port = int(config["bastion_port"])
    timeout = float(config.get("connect_timeout_seconds", 15.0))
    jump_delay = float(config.get("jump_delay_seconds", 1.0))
    target_command = (
        target_command_override
        if target_command_override is not None
        else str(config.get("target_command", ""))
    ).strip()

    status(f"正在连接堡垒机 {host}:{port} ...")
    sock = socket.create_connection((host, port), timeout=timeout)
    configure_socket_keepalive(sock)
    transport = paramiko.Transport(sock)
    transport.start_client(timeout=timeout)
    configure_transport_keepalive(transport, config)

    authenticated = False
    auth_errors: list[str] = []
    allowed_auth_types: list[str] = []

    def interactive_handler(
        title: str, instructions: str, prompts: list[tuple[str, bool]]
    ) -> list[str]:
        responses: list[str] = []
        for prompt, _echo in prompts:
            if _prompt_matches(
                prompt,
                (
                    "password",
                    "passwd",
                    "passcode",
                    "口令",
                    "密码",
                    "credential",
                ),
            ):
                responses.append(password)
            elif _prompt_matches(
                prompt,
                (
                    "otp",
                    "mfa",
                    "verification",
                    "verify",
                    "code",
                    "token",
                    "验证码",
                    "动态",
                    "令牌",
                ),
            ):
                responses.append(mfa_code)
            elif not responses:
                responses.append(password)
            else:
                responses.append(mfa_code)
        return responses

    try:
        try:
            transport.auth_none(username=username)
            authenticated = transport.is_authenticated()
        except BadAuthenticationType as exc:
            allowed_auth_types = list(exc.allowed_types)
            status(f"服务器允许认证方式: {', '.join(allowed_auth_types)}")
        except PartialAuthentication as exc:
            allowed_auth_types = list(exc.allowed_types)
            status(f"服务器要求继续认证: {', '.join(allowed_auth_types)}")
        except AuthenticationException:
            pass

        if authenticated:
            status("已通过 SSH none 方式认证。")
        else:
            status("正在尝试密码认证 ...")
        transport.auth_password(username=username, password=password)
        authenticated = transport.is_authenticated()
    except BadAuthenticationType as exc:
        auth_errors.append(str(exc))
        if "keyboard-interactive" in exc.allowed_types:
            transport.auth_interactive(username=username, handler=interactive_handler)
            authenticated = transport.is_authenticated()
    except PartialAuthentication as exc:
        auth_errors.append(str(exc))
        if "keyboard-interactive" in exc.allowed_types:
            transport.auth_interactive(username=username, handler=interactive_handler)
            authenticated = transport.is_authenticated()
    except AuthenticationException as exc:
        auth_errors.append(str(exc))
        try:
            transport.auth_interactive(username=username, handler=interactive_handler)
            authenticated = transport.is_authenticated()
        except AuthenticationException as second_exc:
            auth_errors.append(str(second_exc))

    if not authenticated:
        transport.close()
        detail = "; ".join(error for error in auth_errors if error)
        if allowed_auth_types:
            detail = f"{detail}; allowed methods: {', '.join(allowed_auth_types)}"
        if mfa_code == "":
            detail = f"{detail}; MFA code was empty"
        raise RuntimeError(f"Bastion authentication failed. {detail}".strip())

    status("认证成功，正在打开远程终端 ...")
    channel = transport.open_session(timeout=timeout)
    channel.get_pty(term=term or "xterm", width=max(40, cols), height=max(10, rows))
    channel.invoke_shell()

    if target_command:
        time.sleep(jump_delay)
        status(f"正在发送目标选择命令 {target_command!r} ...")
        channel.send(target_command + "\r")

    return transport, channel


class PromptResponder:
    def __init__(self, resource_account: str, resource_password: str) -> None:
        self.resource_account = resource_account
        self.resource_password = resource_password
        self.account_sent = False
        self.password_sent = False
        self.buffer = ""

    @property
    def enabled(self) -> bool:
        return bool(self.resource_account and self.resource_password)

    def feed(self, data: bytes, channel: paramiko.Channel) -> None:
        if not self.enabled:
            return
        text = data.decode("utf-8", errors="ignore")
        if not text:
            return
        self.buffer = (self.buffer + text)[-4000:]
        if not self.account_sent and re.search(
            r"(资源.*账户|account)\s*[:：]\s*$", self.buffer, re.IGNORECASE
        ):
            channel.send(self.resource_account + "\r")
            self.account_sent = True
            self.buffer = ""
            return
        if self.account_sent and not self.password_sent and re.search(
            r"(资源.*密码|password)\s*[:：]\s*$", self.buffer, re.IGNORECASE
        ):
            channel.send(self.resource_password + "\r")
            self.password_sent = True
            self.buffer = ""


class WebSocketConnection:
    def __init__(self, handler: BaseHTTPRequestHandler) -> None:
        self.handler = handler
        self.lock = threading.Lock()
        self.closed = False

    def recv(self) -> tuple[int, bytes] | None:
        first = self.handler.rfile.read(2)
        if len(first) < 2:
            self.closed = True
            return None
        b1, b2 = first
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.handler.rfile.read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.handler.rfile.read(8))[0]
        mask_key = self.handler.rfile.read(4) if masked else b""
        payload = self.handler.rfile.read(length) if length else b""
        if masked:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        if opcode == 8:
            self.closed = True
        return opcode, payload

    def send_text(self, text: str) -> None:
        self.send_frame(text.encode("utf-8"), opcode=1)

    def send_json(self, payload: dict[str, Any]) -> None:
        self.send_text(json.dumps(payload, ensure_ascii=False))

    def send_frame(self, payload: bytes, opcode: int = 1) -> None:
        if self.closed:
            return
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(length)
        elif length < (1 << 16):
            header.append(126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(127)
            header.extend(struct.pack("!Q", length))
        with self.lock:
            try:
                self.handler.wfile.write(bytes(header) + payload)
                self.handler.wfile.flush()
            except OSError:
                self.closed = True

    def close(self) -> None:
        if not self.closed:
            try:
                self.send_frame(b"", opcode=8)
            finally:
                self.closed = True


class HelperHTTPHandler(BaseHTTPRequestHandler):
    server_version = "CBHHelper/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    @property
    def helper_config(self) -> dict[str, Any]:
        return self.server.helper_config  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send_html()
        elif path == "/health":
            self._send_json({"ok": True, "app": APP_NAME})
        elif path == "/ws":
            self._handle_ws()
        elif path.startswith("/static/"):
            self._send_static(path)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _send_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self) -> None:
        config = self.helper_config
        body = render_index(config).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, path: str) -> None:
        name = Path(path).name
        file_path = BUNDLE_DIR / "static" / name
        if not file_path.exists() or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_types = {
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
        }
        body = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header(
            "Content-Type",
            content_types.get(file_path.suffix.lower(), "application/octet-stream"),
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_ws(self) -> None:
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            self.send_error(HTTPStatus.BAD_REQUEST, "Missing WebSocket key")
            return
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        self.send_response(HTTPStatus.SWITCHING_PROTOCOLS)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        ws = WebSocketConnection(self)
        handle_web_terminal(ws, self.helper_config)


def handle_web_terminal(ws: WebSocketConnection, config: dict[str, Any]) -> None:
    transport: paramiko.Transport | None = None
    channel: paramiko.Channel | None = None
    stop_event = threading.Event()
    last_shell_activity = {"time": time.time()}

    def send_status(text: str) -> None:
        ws.send_json({"type": "status", "text": text})

    try:
        first = ws.recv()
        if not first:
            return
        _opcode, payload = first
        start = json.loads(payload.decode("utf-8"))
        username = str(start.get("username", "")).strip()
        password = str(start.get("password", ""))
        mfa_code = str(start.get("mfa", ""))
        target_command = str(start.get("targetCommand", "")).strip()
        resource_account = str(start.get("resourceAccount", "")).strip()
        resource_password = str(start.get("resourcePassword", ""))
        cache_for_cmd = bool(start.get("cacheForCmd", True))
        cols = int(start.get("cols", 100) or 100)
        rows = int(start.get("rows", 30) or 30)
        term = str(start.get("term", "xterm"))

        if not username or not password:
            ws.send_json({"type": "error", "text": "必须填写堡垒机用户名和密码。"})
            return

        transport, channel = open_bastion_shell(
            config,
            username=username,
            password=password,
            mfa_code=mfa_code,
            cols=cols,
            rows=rows,
            term=term,
            target_command_override=target_command,
            on_status=send_status,
        )
        responder = PromptResponder(resource_account, resource_password)
        if cache_for_cmd:
            ttl = int(config.get("credential_cache_ttl_seconds", 0))
            CREDENTIAL_CACHE.set(
                username=username,
                password=password,
                mfa_code=mfa_code,
                target_command=target_command,
                resource_account=resource_account,
                resource_password=resource_password,
                ttl_seconds=ttl,
            )
            if ttl <= 0:
                send_status("已为本地 SSH 缓存凭据，直到服务停止。")
            else:
                send_status(f"已为本地 SSH 缓存凭据，有效期 {ttl} 秒。")

        def pump_remote() -> None:
            assert channel is not None
            while not stop_event.is_set() and not ws.closed:
                try:
                    if channel.recv_ready():
                        data = channel.recv(8192)
                        if not data:
                            break
                        last_shell_activity["time"] = time.time()
                        ws.send_json(
                            {
                                "type": "data",
                                "data": data.decode("utf-8", errors="replace"),
                            }
                        )
                        responder.feed(data, channel)
                    elif channel.exit_status_ready():
                        break
                    else:
                        time.sleep(0.02)
                except Exception as exc:
                    ws.send_json({"type": "error", "text": str(exc)})
                    break
            ws.close()

        reader = threading.Thread(target=pump_remote, daemon=True)
        reader.start()

        def pump_websocket_keepalive() -> None:
            interval = int(config.get("websocket_keepalive_seconds", 30))
            if interval <= 0:
                return
            while not stop_event.wait(interval):
                if ws.closed:
                    break
                ws.send_frame(b"cbh", opcode=9)

        websocket_keepalive = threading.Thread(
            target=pump_websocket_keepalive,
            daemon=True,
        )
        websocket_keepalive.start()

        def pump_shell_keepalive() -> None:
            interval = int(config.get("web_terminal_shell_keepalive_seconds", 60))
            if interval <= 0:
                return
            while not stop_event.wait(interval):
                if ws.closed or channel is None or channel.closed:
                    break
                idle_seconds = time.time() - last_shell_activity["time"]
                if idle_seconds >= interval:
                    try:
                        channel.send("\x05")
                        last_shell_activity["time"] = time.time()
                    except Exception:
                        break

        shell_keepalive = threading.Thread(
            target=pump_shell_keepalive,
            daemon=True,
        )
        shell_keepalive.start()

        while not ws.closed and not stop_event.is_set():
            frame = ws.recv()
            if not frame:
                break
            opcode, data = frame
            if opcode == 8:
                break
            if opcode == 9:
                ws.send_frame(data, opcode=10)
                continue
            if opcode not in (1, 2):
                continue
            message = json.loads(data.decode("utf-8"))
            if message.get("type") == "noop":
                continue
            if message.get("type") == "input" and channel:
                last_shell_activity["time"] = time.time()
                channel.send(str(message.get("data", "")))
            elif message.get("type") == "resize" and channel:
                channel.resize_pty(
                    width=max(40, int(message.get("cols", 100) or 100)),
                    height=max(10, int(message.get("rows", 30) or 30)),
                )
    except Exception as exc:
        ws.send_json({"type": "error", "text": str(exc)})
    finally:
        stop_event.set()
        if channel is not None:
            channel.close()
        if transport is not None:
            transport.close()
        ws.close()


class LocalSSHServer(paramiko.ServerInterface):
    def __init__(self) -> None:
        self.event = threading.Event()
        self.username = ""
        self.term = "xterm"
        self.cols = 100
        self.rows = 30
        self.remote_channel: paramiko.Channel | None = None
        self.exec_command: str | None = None

    def check_auth_none(self, username: str) -> int:
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "none,password,publickey"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        self.term = term.decode("ascii", errors="replace") if isinstance(term, bytes) else str(term)
        self.cols = width or 100
        self.rows = height or 30
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.exec_command = command.decode("utf-8", errors="replace")
        self.event.set()
        return True

    def check_channel_window_change_request(
        self,
        channel: paramiko.Channel,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
    ) -> bool:
        self.cols = width or self.cols
        self.rows = height or self.rows
        if self.remote_channel is not None:
            try:
                self.remote_channel.resize_pty(width=self.cols, height=self.rows)
            except Exception:
                pass
        return True


def channel_write(channel: paramiko.Channel, text: str) -> None:
    channel.sendall(text.replace("\n", "\r\n").encode("utf-8", errors="replace"))


def clean_terminal_text(text: str) -> str:
    text = ANSI_OSC_RE.sub("", text)
    text = ANSI_CSI_RE.sub("", text)
    text = ANSI_SIMPLE_RE.sub("", text)

    chars: list[str] = []
    for char in text:
        if char == "\b":
            if chars:
                chars.pop()
            continue
        chars.append(char)

    text = "".join(chars)
    text = NON_TEXT_CONTROL_RE.sub("", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def build_mcp_exec_wrapper(command: str, begin_marker: str, end_marker: str) -> str:
    normalized = command.replace("\r\n", "\n").replace("\r", "\n")
    encoded = base64.b64encode(normalized.encode("utf-8")).decode("ascii")
    encoded_lines = "\n".join(
        encoded[index : index + 76] for index in range(0, len(encoded), 76)
    )
    payload_marker = f"__CBH_MCP_PAYLOAD_{uuid.uuid4().hex}__"
    run_line = (
        f"if base64 -d \"$__CBH_B64\" > \"$__CBH_TMP\" 2>/dev/null; then "
        "chmod 700 \"$__CBH_TMP\" 2>/dev/null || true; "
        f"printf '\\n{begin_marker}\\n'; "
        "/bin/bash \"$__CBH_TMP\" 2>&1; "
        "__CBH_RC=$?; "
        "else "
        "__CBH_RC=125; "
        f"printf '\\n{begin_marker}\\n'; "
        "printf 'Failed to decode MCP command payload\\n' >&2; "
        "fi; "
        "rm -f \"$__CBH_TMP\" \"$__CBH_B64\" 2>/dev/null || true; "
        f"printf '\\n{end_marker}:%s\\n' \"$__CBH_RC\"; "
        "stty echo 2>/dev/null || true"
    )
    return "\n".join(
        [
            "export TERM=dumb NO_COLOR=1 CLICOLOR=0",
            "PS1= PS2=",
            "trap 'stty echo 2>/dev/null || true' EXIT",
            "__CBH_TMP=$(mktemp /tmp/cbh-mcp.XXXXXX 2>/dev/null || printf '/tmp/cbh-mcp-%s' $$)",
            '__CBH_B64="$__CBH_TMP.b64"',
            f"cat > \"$__CBH_B64\" <<'{payload_marker}'",
            encoded_lines,
            payload_marker,
            run_line,
        ]
    )


def drain_remote_output(
    remote_channel: paramiko.Channel,
    quiet_seconds: float = 0.25,
    timeout_seconds: float = 2.0,
) -> None:
    deadline = time.time() + timeout_seconds
    quiet_deadline = time.time() + quiet_seconds
    while time.time() < deadline:
        if remote_channel.recv_ready():
            data = remote_channel.recv(8192)
            if not data:
                return
            quiet_deadline = time.time() + quiet_seconds
        elif time.time() >= quiet_deadline:
            return
        else:
            time.sleep(0.05)


def find_exact_marker_line_end(buffer: str, marker: str) -> int | None:
    search_at = 0
    while True:
        marker_index = buffer.find(marker, search_at)
        if marker_index < 0:
            return None
        line_start = buffer.rfind("\n", 0, marker_index) + 1
        line_end = buffer.find("\n", marker_index)
        if line_end < 0:
            return None
        if buffer[line_start:line_end].strip() == marker:
            return line_end + 1
        search_at = marker_index + len(marker)


def find_end_marker_line(buffer: str, marker: str) -> tuple[int, int, int] | None:
    search_at = 0
    pattern = re.compile(rf"^{re.escape(marker)}:(\d+)$")
    while True:
        marker_index = buffer.find(marker, search_at)
        if marker_index < 0:
            return None
        line_start = buffer.rfind("\n", 0, marker_index) + 1
        line_end = buffer.find("\n", marker_index)
        if line_end < 0:
            return None
        match = pattern.match(buffer[line_start:line_end].strip())
        if match:
            return line_start, line_end + 1, int(match.group(1))
        search_at = marker_index + len(marker)


def wait_for_target_shell(
    remote_channel: paramiko.Channel,
    responder: PromptResponder,
    timeout_seconds: int,
) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if remote_channel.recv_ready():
            data = remote_channel.recv(8192)
            if not data:
                return False
            responder.feed(data, remote_channel)
            if responder.password_sent:
                quiet_deadline = time.time() + 0.5
                while time.time() < quiet_deadline:
                    if remote_channel.recv_ready():
                        more = remote_channel.recv(8192)
                        if not more:
                            return False
                        responder.feed(more, remote_channel)
                        quiet_deadline = time.time() + 0.5
                    else:
                        time.sleep(0.05)
                return True
        elif remote_channel.exit_status_ready():
            return False
        else:
            time.sleep(0.05)
    return False


def channel_read_line(
    channel: paramiko.Channel,
    prompt: str,
    default: str = "",
    secret: bool = False,
) -> str:
    if default:
        channel_write(channel, f"{prompt} [{default}]: ")
    else:
        channel_write(channel, f"{prompt}: ")
    chars: list[str] = []
    while True:
        data = channel.recv(1)
        if not data:
            raise RuntimeError("Local SSH client disconnected.")
        char = data.decode("utf-8", errors="ignore")
        if char in ("\r", "\n"):
            channel_write(channel, "\n")
            value = "".join(chars)
            return value if value else default
        if char in ("\x7f", "\b"):
            if chars:
                chars.pop()
                if not secret:
                    channel.send("\b \b")
            continue
        if char == "\x03":
            raise KeyboardInterrupt
        chars.append(char)
        if not secret:
            channel.send(char)


def bridge_channels(
    local: paramiko.Channel,
    remote: paramiko.Channel,
    responder: PromptResponder | None = None,
) -> None:
    while True:
        if local.closed or remote.closed:
            break
        try:
            if local.recv_ready():
                data = local.recv(8192)
                if not data:
                    break
                remote.send(data)
            if remote.recv_ready():
                data = remote.recv(8192)
                if not data:
                    break
                local.send(data)
                if responder is not None:
                    responder.feed(data, remote)
            if remote.exit_status_ready():
                break
            time.sleep(0.01)
        except OSError:
            break


def handle_local_exec_request(
    channel: paramiko.Channel,
    config: dict[str, Any],
    server: LocalSSHServer,
    command: str,
) -> None:
    cached = CREDENTIAL_CACHE.get()
    if cached is None:
        channel_write(
            channel,
            f"No cached web credentials in this cbh-helper process (pid {os.getpid()}). Open the web terminal, connect successfully, and keep sharing enabled.\n",
        )
        channel.send_exit_status(1)
        return

    responder = PromptResponder(cached.resource_account, cached.resource_password)
    if not responder.enabled:
        channel_write(
            channel,
            "Cached resource account/password are missing. Fill Resource account and Resource password in the web terminal first.\n",
        )
        channel.send_exit_status(1)
        return

    remote_transport: paramiko.Transport | None = None
    remote_channel: paramiko.Channel | None = None
    request_id = uuid.uuid4().hex
    begin_marker = f"__CBH_MCP_BEGIN_{request_id}__"
    end_marker = f"__CBH_MCP_END_{request_id}__"
    append_exit_code = bool(config.get("mcp_exec_append_exit_code", False))
    strip_controls = bool(config.get("mcp_exec_strip_terminal_controls", True))
    serialize_login = bool(config.get("mcp_exec_serialize_login", True))
    login_lock_timeout = int(config.get("mcp_exec_login_lock_timeout_seconds", 120))

    def emit_output(text: str) -> None:
        if not text:
            return
        if strip_controls:
            text = clean_terminal_text(text)
        else:
            text = text.replace("\r\n", "\n").replace("\r", "\n")
        if text:
            channel.sendall(text.encode("utf-8", errors="replace"))

    try:
        login_lock_acquired = False
        try:
            if serialize_login:
                login_lock_acquired = MCP_EXEC_LOGIN_LOCK.acquire(
                    timeout=login_lock_timeout
                )
                if not login_lock_acquired:
                    channel_write(
                        channel,
                        "Timed out waiting for another MCP exec login to finish.\n",
                    )
                    channel.send_exit_status(124)
                    return

            remote_transport, remote_channel = open_bastion_shell(
                config,
                username=cached.username,
                password=cached.password,
                mfa_code=cached.mfa_code,
                cols=server.cols,
                rows=server.rows,
                term=server.term,
                target_command_override=cached.target_command,
                on_status=None,
            )

            ready_timeout = int(config.get("mcp_exec_ready_timeout_seconds", 60))
            if not wait_for_target_shell(remote_channel, responder, ready_timeout):
                channel_write(
                    channel,
                    "Timed out before target shell became ready. Confirm the web terminal cached resource account/password and selected target profile.\n",
                )
                channel.send_exit_status(1)
                return

            remote_channel.sendall(b"stty -echo 2>/dev/null || true\r")
            drain_remote_output(remote_channel)

            wrapper = build_mcp_exec_wrapper(command, begin_marker, end_marker)
            remote_channel.sendall(
                (wrapper.replace("\n", "\r") + "\r").encode("utf-8", errors="replace")
            )
        finally:
            if login_lock_acquired:
                MCP_EXEC_LOGIN_LOCK.release()

        buffer = ""
        capture_started = False
        exit_status = 124
        deadline = time.time() + int(config.get("mcp_exec_timeout_seconds", 300))
        flush_limit = 65536
        keep_tail = max(len(end_marker) + 512, 4096)
        while time.time() < deadline:
            if remote_channel.recv_ready():
                data = remote_channel.recv(8192)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                buffer += text

                if not capture_started:
                    begin_line_end = find_exact_marker_line_end(buffer, begin_marker)
                    if begin_line_end is None:
                        if len(buffer) > keep_tail:
                            buffer = buffer[-keep_tail:]
                        continue
                    buffer = buffer[begin_line_end:]
                    capture_started = True

                end_match = find_end_marker_line(buffer, end_marker)
                if end_match is not None:
                    end_line_start, _end_line_end, exit_status = end_match
                    before = buffer[:end_line_start]
                    if before:
                        emit_output(before)
                    if append_exit_code:
                        emit_output(f"\nCBH_MCP_RC={exit_status}\n")
                    channel.send_exit_status(exit_status)
                    return
                if len(buffer) > flush_limit:
                    emit_output(buffer[:-keep_tail])
                    buffer = buffer[-keep_tail:]
            elif remote_channel.exit_status_ready():
                break
            else:
                time.sleep(0.05)

        if buffer and capture_started:
            emit_output(buffer)
        elif buffer:
            emit_output(buffer)
            channel_write(channel, "\nTimed out waiting for command start marker.\n")
            channel.send_exit_status(124)
            return
        channel_write(channel, "\nTimed out waiting for command completion marker.\n")
        channel.send_exit_status(124)
    except Exception as exc:
        channel_write(channel, f"Error: {exc}\n")
        channel.send_exit_status(1)
    finally:
        if remote_channel is not None:
            remote_channel.close()
        if remote_transport is not None:
            remote_transport.close()


def handle_local_ssh_client(
    client: socket.socket,
    addr: tuple[str, int],
    config: dict[str, Any],
    host_key: paramiko.RSAKey,
) -> None:
    transport: paramiko.Transport | None = None
    remote_transport: paramiko.Transport | None = None
    channel: paramiko.Channel | None = None
    remote_channel: paramiko.Channel | None = None
    try:
        configure_socket_keepalive(client)
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = LocalSSHServer()
        transport.start_server(server=server)
        configure_transport_keepalive(transport, config)
        channel = transport.accept(20)
        if channel is None:
            return
        server.event.wait(15)
        if not server.event.is_set():
            channel.close()
            return
        if server.exec_command is not None:
            handle_local_exec_request(channel, config, server, server.exec_command)
            return

        cached = CREDENTIAL_CACHE.get()
        suppress_cached_login_prelude = False
        if cached is not None:
            username = cached.username
            password = cached.password
            mfa_code = cached.mfa_code
            target_command = cached.target_command or str(config.get("target_command", "")).strip()
            responder = PromptResponder(cached.resource_account, cached.resource_password)
            suppress_cached_login_prelude = responder.enabled and bool(
                config.get("local_ssh_suppress_cached_login_prelude", True)
            )
            if not suppress_cached_login_prelude:
                if cached.remaining_seconds < 0:
                    channel_write(channel, "Using cached web credentials.\n")
                else:
                    channel_write(
                        channel,
                        f"Using cached web credentials. Expires in {cached.remaining_seconds} seconds.\n",
                    )
                if responder.enabled:
                    channel_write(channel, "Resource account/password auto-answer is enabled.\n")
                else:
                    channel_write(
                        channel,
                        "Resource account/password are not cached; enter target prompts manually.\n",
                    )
        else:
            configured_user = str(config.get("bastion_username", "")).strip()
            local_user = getpass.getuser().lower()
            explicit_ssh_user = (
                server.username
                and server.username.lower() not in ("unknown", local_user)
            )
            if explicit_ssh_user:
                default_user = server.username
            else:
                default_user = configured_user

            if configured_user and (not explicit_ssh_user or default_user == configured_user):
                username = configured_user
                channel_write(channel, f"Bastion username: {username}\n")
            else:
                username = channel_read_line(channel, "Bastion username", default=default_user)
            password = channel_read_line(channel, "Bastion password", secret=True)
            mfa_code = channel_read_line(channel, "MFA code, press Enter to skip", secret=False)
            target_command = str(config.get("target_command", "")).strip()
            responder = PromptResponder("", "")
        if not suppress_cached_login_prelude:
            channel_write(channel, f"{APP_NAME} local SSH bridge\n")
            channel_write(
                channel,
                f"Bastion: {config['bastion_host']}:{config['bastion_port']}\n",
            )
            channel_write(channel, f"Target selector: {target_command}\n\n")

        def status(message: str) -> None:
            if not suppress_cached_login_prelude:
                channel_write(channel, message + "\n")

        remote_transport, remote_channel = open_bastion_shell(
            config,
            username=username,
            password=password,
            mfa_code=mfa_code,
            cols=server.cols,
            rows=server.rows,
            term=server.term,
            target_command_override=target_command,
            on_status=None if suppress_cached_login_prelude else status,
        )
        server.remote_channel = remote_channel
        if suppress_cached_login_prelude:
            ready_timeout = int(config.get("mcp_exec_ready_timeout_seconds", 60))
            if not wait_for_target_shell(remote_channel, responder, ready_timeout):
                channel_write(
                    channel,
                    "Timed out before target shell became ready. Confirm the web terminal cached resource account/password and selected target profile.\n",
                )
                return
            remote_channel.send("\r")
        else:
            channel_write(channel, "Connected. Handing over terminal.\n\n")
        bridge_channels(channel, remote_channel, responder=responder)
    except KeyboardInterrupt:
        if channel is not None:
            channel_write(channel, "\nCanceled.\n")
    except Exception as exc:
        if channel is not None and not channel.closed:
            channel_write(channel, f"\nError: {exc}\n")
        else:
            print(f"Local SSH client {addr} failed: {exc}", file=sys.stderr)
    finally:
        if remote_channel is not None:
            remote_channel.close()
        if remote_transport is not None:
            remote_transport.close()
        if channel is not None:
            channel.close()
        if transport is not None:
            transport.close()
        try:
            client.close()
        except OSError:
            pass


class LocalSSHListener(threading.Thread):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(daemon=True)
        self.config = config
        self.sock: socket.socket | None = None
        self.ready = threading.Event()
        self.stop_event = threading.Event()

    def run(self) -> None:
        host = str(self.config["local_ssh_host"])
        port = int(self.config["local_ssh_port"])
        key_path = Path(str(self.config.get("local_host_key_path", "cbh-local-hostkey.key")))
        if not key_path.is_absolute():
            key_path = APP_DIR / key_path
        host_key = ensure_host_key(key_path)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(100)
        self.sock.settimeout(1.0)
        self.ready.set()
        while not self.stop_event.is_set():
            try:
                client, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    break
                raise
            threading.Thread(
                target=handle_local_ssh_client,
                args=(client, addr, self.config, host_key),
                daemon=True,
            ).start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass


class HelperHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], config: dict[str, Any]) -> None:
        self.helper_config = config
        super().__init__(server_address, HelperHTTPHandler)


def render_index(config: dict[str, Any]) -> str:
    bastion = html.escape(f"{config['bastion_host']}:{config['bastion_port']}")
    default_username = html.escape(str(config.get("bastion_username", "")))
    default_resource_account = html.escape(
        str(config.get("default_resource_account", "root"))
    )
    profiles = config.get("target_profiles") or []
    if not isinstance(profiles, list) or not profiles:
        profiles = [
            {
                "name": str(config.get("target_command", "default")),
                "target_command": str(config.get("target_command", "")),
                "resource_account": str(config.get("default_resource_account", "root")),
            }
        ]
    profile_json = json.dumps(profiles, ensure_ascii=False).replace("</", "<\\/")
    default_target_command = str(
        profiles[0].get("target_command", config.get("target_command", ""))
    )
    default_target_label = str(profiles[0].get("name") or default_target_command)
    selector = html.escape(default_target_label)
    default_target_command_value = html.escape(default_target_command)
    ssh_command = html.escape(
        f"ssh 127.0.0.1 -p {int(config['local_ssh_port'])}"
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{APP_NAME} v{APP_VERSION}</title>
  <link rel="stylesheet" href="/static/xterm.css">
  <script src="/static/xterm.min.js"></script>
  <script src="/static/xterm-addon-fit.min.js"></script>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #101214;
      --panel: #171a1d;
      --line: #2b3137;
      --text: #edf0f2;
      --muted: #9aa6b2;
      --accent: #32c48d;
      --danger: #ff6b6b;
    }}
    * {{ box-sizing: border-box; }}
    html, body {{
      height: 100%;
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
      letter-spacing: 0;
    }}
    body {{
      display: grid;
      grid-template-rows: auto 1fr;
      min-height: 100svh;
    }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 16px;
      align-items: center;
      padding: 14px 18px;
      border-bottom: 1px solid var(--line);
      background: #121518;
    }}
    h1 {{
      margin: 0;
      font-size: 18px;
      font-weight: 650;
      line-height: 1.2;
    }}
    .app-version {{
      margin-left: 8px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 500;
    }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 6px;
      color: var(--muted);
      font-family: Consolas, monospace;
      font-size: 12px;
    }}
    .header-tools {{
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 12px;
      min-width: 0;
    }}
    .language-control {{
      display: flex;
      align-items: center;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }}
    .language-control label {{
      margin: 0;
    }}
    .language-control select {{
      width: 92px;
      height: 30px;
      margin: 0;
      font-size: 12px;
    }}
    .ssh-command {{
      color: var(--accent);
      font-family: Consolas, monospace;
      font-size: 13px;
      white-space: nowrap;
    }}
    main {{
      display: grid;
      grid-template-columns: 340px 1fr;
      min-height: 0;
    }}
    aside {{
      padding: 16px;
      border-right: 1px solid var(--line);
      background: var(--panel);
    }}
    label {{
      display: block;
      margin: 0 0 6px;
      color: var(--muted);
      font-size: 12px;
    }}
    input,
    select {{
      width: 100%;
      height: 36px;
      margin: 0 0 12px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      outline: none;
      background: #0f1113;
      color: var(--text);
      font-size: 14px;
    }}
    input:focus,
    select:focus {{
      border-color: var(--accent);
    }}
    button {{
      width: 100%;
      height: 38px;
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: #07120d;
      font-weight: 700;
      cursor: pointer;
    }}
    button:disabled {{
      opacity: 0.55;
      cursor: not-allowed;
    }}
    .form-actions {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }}
    button.secondary {{
      border: 1px solid var(--line);
      background: #1a1f24;
      color: var(--text);
    }}
    .check-row {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0 0 12px;
      color: var(--muted);
      font-size: 12px;
    }}
    .check-row input {{
      width: 16px;
      height: 16px;
      margin: 0;
    }}
    .check-row label {{
      margin: 0;
      color: var(--muted);
    }}
    .status {{
      min-height: 22px;
      margin-top: 12px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
      overflow-wrap: anywhere;
    }}
    .status.error {{ color: var(--danger); }}
    .terminal-shell {{
      min-width: 0;
      min-height: 0;
      padding: 10px;
      background: #0b0d0f;
    }}
    #terminal {{
      width: 100%;
      height: 100%;
      min-height: 360px;
    }}
    @media (max-width: 900px) {{
      header {{ grid-template-columns: 1fr; }}
      .header-tools {{ justify-content: flex-start; flex-wrap: wrap; }}
      .ssh-command {{ white-space: normal; }}
      main {{ grid-template-columns: 1fr; grid-template-rows: auto 1fr; }}
      aside {{ border-right: 0; border-bottom: 1px solid var(--line); }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1><span data-i18n="title">CBH 辅助连接</span><span class="app-version">v{APP_VERSION}</span></h1>
      <div class="meta">
        <span><span data-i18n="bastion">堡垒机</span> {bastion}</span>
        <span><span data-i18n="target">目标</span> <span id="target-summary">{selector}</span></span>
      </div>
    </div>
    <div class="header-tools">
      <div class="language-control">
        <label for="language" data-i18n="language">语言</label>
        <select id="language" name="language">
          <option value="zh" selected>中文</option>
          <option value="en">English</option>
        </select>
      </div>
      <div class="ssh-command">{ssh_command}</div>
    </div>
  </header>
  <main>
    <aside>
      <form id="login">
        <label for="username" data-i18n="bastionUsername">堡垒机用户名</label>
        <input id="username" name="username" autocomplete="username" value="{default_username}" required>
        <label for="password" data-i18n="bastionPassword">堡垒机密码</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <label for="mfa" data-i18n="mfaCode">MFA 验证码</label>
        <input id="mfa" name="mfa" autocomplete="one-time-code">
        <label for="target-profile" data-i18n="targetProfile">目标资源</label>
        <select id="target-profile" name="target-profile"></select>
        <label for="target-command" data-i18n="targetSelector">目标选择命令</label>
        <input id="target-command" name="target-command" value="{default_target_command_value}" autocomplete="off">
        <label for="resource-account-profile" data-i18n="resourceAccountProfile">资源账号选项</label>
        <select id="resource-account-profile" name="resource-account-profile"></select>
        <label for="resource-account" data-i18n="resourceAccount">资源账号</label>
        <input id="resource-account" name="resource-account" value="{default_resource_account}" autocomplete="off">
        <label for="resource-password" data-i18n="resourcePassword">资源密码</label>
        <input id="resource-password" name="resource-password" type="password" autocomplete="off">
        <div class="check-row">
          <input id="cache-for-cmd" name="cache-for-cmd" type="checkbox" checked>
          <label for="cache-for-cmd" data-i18n="shareLogin">共享本次登录给本地 SSH</label>
        </div>
        <div class="form-actions">
          <button id="connect" type="submit" data-i18n="connect">连接</button>
          <button id="reconnect" class="secondary" type="button" data-i18n="reconnect" disabled>重连</button>
        </div>
      </form>
      <div id="status" class="status" data-i18n="idle">空闲。</div>
    </aside>
    <section class="terminal-shell" aria-label="terminal">
      <div id="terminal"></div>
    </section>
  </main>
  <script id="target-profiles" type="application/json">{profile_json}</script>
  <script>
    const targetProfiles = JSON.parse(document.getElementById("target-profiles").textContent);
    const translations = {{
      zh: {{
        title: "CBH 辅助连接",
        bastion: "堡垒机",
        target: "目标",
        language: "语言",
        bastionUsername: "堡垒机用户名",
        bastionPassword: "堡垒机密码",
        mfaCode: "MFA 验证码",
        targetProfile: "目标资源",
        targetSelector: "目标选择命令",
        resourceAccountProfile: "资源账号选项",
        customResourceAccount: "自定义账号",
        resourceAccount: "资源账号",
        resourcePassword: "资源密码",
        shareLogin: "共享本次登录给本地 SSH",
        connect: "连接",
        reconnect: "重连",
        idle: "空闲。",
        ready: "就绪。",
        connecting: "正在连接。",
        disconnected: "已断开。",
        connectionError: "连接错误。"
      }},
      en: {{
        title: "CBH Helper",
        bastion: "Bastion",
        target: "Target",
        language: "Language",
        bastionUsername: "Bastion username",
        bastionPassword: "Bastion password",
        mfaCode: "MFA code",
        targetProfile: "Target profile",
        targetSelector: "Target selector",
        resourceAccountProfile: "Resource account option",
        customResourceAccount: "Custom account",
        resourceAccount: "Resource account",
        resourcePassword: "Resource password",
        shareLogin: "Share this login with local SSH",
        connect: "Connect",
        reconnect: "Reconnect",
        idle: "Idle.",
        ready: "Ready.",
        connecting: "Connecting.",
        disconnected: "Disconnected.",
        connectionError: "Connection error."
      }}
    }};
    let currentLanguage = "zh";

    function t(key) {{
      return (translations[currentLanguage] && translations[currentLanguage][key]) || translations.zh[key] || key;
    }}

    function setLanguage(language) {{
      currentLanguage = translations[language] ? language : "zh";
      localStorage.setItem("cbh-helper-language", currentLanguage);
      document.documentElement.lang = currentLanguage === "zh" ? "zh-CN" : "en";
      document.querySelectorAll("[data-i18n]").forEach((node) => {{
        const key = node.getAttribute("data-i18n");
        if (key && translations[currentLanguage][key]) {{
          node.textContent = translations[currentLanguage][key];
        }}
      }});
      const accountSelect = document.getElementById("resource-account-profile");
      if (accountSelect) {{
        const customOption = accountSelect.querySelector("option[value='__custom__']");
        if (customOption) {{
          customOption.textContent = t("customResourceAccount");
        }}
      }}
    }}

    const terminal = new Terminal({{
      cursorBlink: true,
      convertEol: true,
      fontFamily: "Consolas, 'Cascadia Mono', monospace",
      fontSize: 14,
      theme: {{
        background: "#0b0d0f",
        foreground: "#edf0f2",
        cursor: "#32c48d"
      }}
    }});
    const fitAddon = new FitAddon.FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(document.getElementById("terminal"));
    fitAddon.fit();
    terminal.writeln(t("ready"));

    const form = document.getElementById("login");
    const button = document.getElementById("connect");
    const reconnectButton = document.getElementById("reconnect");
    const statusEl = document.getElementById("status");
    const language = document.getElementById("language");
    const targetSummary = document.getElementById("target-summary");
    const targetProfile = document.getElementById("target-profile");
    const targetCommand = document.getElementById("target-command");
    const resourceAccountProfile = document.getElementById("resource-account-profile");
    const resourceAccount = document.getElementById("resource-account");
    const resourcePassword = document.getElementById("resource-password");
    const defaultResourceAccount = resourceAccount.value || "root";
    const resourcePasswordMemory = new Map();
    const RESOURCE_ACCOUNT_CUSTOM = "__custom__";
    let currentResourcePasswordKey = "";
    let socket = null;
    let wsKeepaliveTimer = null;

    function selectedProfile() {{
      return targetProfiles[Number(targetProfile.value || 0)] || targetProfiles[0] || {{}};
    }}

    function normalizeAccounts(profile) {{
      const accounts = Array.isArray(profile.accounts) ? profile.accounts.slice() : [];
      const legacyAccount = String(profile.resource_account || "").trim();
      if (legacyAccount && !accounts.some((entry) => String(entry.account || "").trim() === legacyAccount)) {{
        accounts.unshift({{
          account: legacyAccount,
          target_command: profile.target_command || "",
          resource_password: ""
        }});
      }}
      return accounts.filter((entry) => String(entry.account || "").trim());
    }}

    function passwordKey(profile, account, command) {{
      return `${{profile.name || ""}}|${{command || ""}}|${{account || ""}}`;
    }}

    function rememberCurrentResourcePassword() {{
      if (currentResourcePasswordKey) {{
        resourcePasswordMemory.set(currentResourcePasswordKey, resourcePassword.value);
      }}
    }}

    function setResourcePassword(profile, account, command, fallbackPassword = "") {{
      currentResourcePasswordKey = passwordKey(profile, account, command);
      resourcePassword.value = resourcePasswordMemory.has(currentResourcePasswordKey)
        ? resourcePasswordMemory.get(currentResourcePasswordKey)
        : fallbackPassword;
    }}

    function applyResourceAccount(profile, value) {{
      const accounts = normalizeAccounts(profile);
      const index = Number(value);
      if (value !== RESOURCE_ACCOUNT_CUSTOM && Number.isInteger(index) && accounts[index]) {{
        const accountProfile = accounts[index];
        const account = String(accountProfile.account || "").trim();
        const command = accountProfile.target_command || profile.target_command || "";
        targetCommand.value = command;
        resourceAccount.value = account;
        resourceAccount.readOnly = true;
        setResourcePassword(profile, account, command, accountProfile.resource_password || "");
        return;
      }}

      const command = profile.target_command || "";
      targetCommand.value = command;
      resourceAccount.readOnly = false;
      resourceAccount.value = profile.resource_account || resourceAccount.value || defaultResourceAccount;
      setResourcePassword(profile, resourceAccount.value, command);
    }}

    function installResourceAccounts(profile) {{
      resourceAccountProfile.innerHTML = "";
      const customOption = document.createElement("option");
      customOption.value = RESOURCE_ACCOUNT_CUSTOM;
      customOption.textContent = t("customResourceAccount");
      resourceAccountProfile.appendChild(customOption);

      normalizeAccounts(profile).forEach((accountProfile, index) => {{
        const option = document.createElement("option");
        option.value = String(index);
        option.textContent = accountProfile.account || `Account ${{index + 1}}`;
        resourceAccountProfile.appendChild(option);
      }});

      resourceAccountProfile.value = RESOURCE_ACCOUNT_CUSTOM;
      applyResourceAccount(profile, RESOURCE_ACCOUNT_CUSTOM);
    }}

    function applyProfile(index) {{
      rememberCurrentResourcePassword();
      const profile = targetProfiles[index] || targetProfiles[0] || {{}};
      targetSummary.textContent = profile.name || profile.target_command || "";
      targetCommand.value = profile.target_command || "";
      installResourceAccounts(profile);
    }}

    function installProfiles() {{
      targetProfiles.forEach((profile, index) => {{
        const option = document.createElement("option");
        option.value = String(index);
        option.textContent = profile.name || profile.target_command || `Target ${{index + 1}}`;
        targetProfile.appendChild(option);
      }});
      applyProfile(0);
    }}

    targetProfile.addEventListener("change", () => {{
      applyProfile(Number(targetProfile.value || 0));
    }});

    resourceAccountProfile.addEventListener("change", () => {{
      rememberCurrentResourcePassword();
      applyResourceAccount(selectedProfile(), resourceAccountProfile.value);
    }});

    resourceAccount.addEventListener("input", () => {{
      if (resourceAccountProfile.value === RESOURCE_ACCOUNT_CUSTOM) {{
        const profile = selectedProfile();
        currentResourcePasswordKey = passwordKey(profile, resourceAccount.value, targetCommand.value);
      }}
    }});

    resourcePassword.addEventListener("input", () => {{
      rememberCurrentResourcePassword();
    }});

    function setStatus(text, error = false) {{
      statusEl.textContent = text;
      statusEl.classList.toggle("error", error);
    }}

    language.value = localStorage.getItem("cbh-helper-language") || "zh";
    setLanguage(language.value);
    language.addEventListener("change", () => {{
      setLanguage(language.value);
    }});

    function wsUrl() {{
      const scheme = location.protocol === "https:" ? "wss" : "ws";
      return `${{scheme}}://${{location.host}}/ws`;
    }}

    function stopWsKeepalive() {{
      if (wsKeepaliveTimer) {{
        clearInterval(wsKeepaliveTimer);
        wsKeepaliveTimer = null;
      }}
    }}

    function connectWebTerminal() {{
      if (socket) {{
        const previousSocket = socket;
        stopWsKeepalive();
        previousSocket.close();
        socket = null;
      }}
      terminal.clear();
      fitAddon.fit();
      const nextSocket = new WebSocket(wsUrl());
      socket = nextSocket;
      button.disabled = true;
      reconnectButton.disabled = true;
      setStatus(t("connecting"));

      nextSocket.addEventListener("open", () => {{
        rememberCurrentResourcePassword();
        const payload = {{
          type: "start",
          username: document.getElementById("username").value,
          password: document.getElementById("password").value,
          mfa: document.getElementById("mfa").value,
          targetCommand: document.getElementById("target-command").value,
          resourceAccount: document.getElementById("resource-account").value,
          resourcePassword: document.getElementById("resource-password").value,
          cacheForCmd: document.getElementById("cache-for-cmd").checked,
          cols: terminal.cols,
          rows: terminal.rows,
          term: "xterm"
        }};
        nextSocket.send(JSON.stringify(payload));
        stopWsKeepalive();
        wsKeepaliveTimer = setInterval(() => {{
          if (nextSocket.readyState === WebSocket.OPEN) {{
            nextSocket.send(JSON.stringify({{ type: "noop" }}));
          }}
        }}, 30000);
        reconnectButton.disabled = false;
      }});

      nextSocket.addEventListener("message", (event) => {{
        const message = JSON.parse(event.data);
        if (message.type === "data") {{
          terminal.write(message.data);
        }} else if (message.type === "status") {{
          setStatus(message.text);
          terminal.writeln(`\\r\\n[${{message.text}}]`);
        }} else if (message.type === "error") {{
          setStatus(message.text, true);
          const errorLabel = currentLanguage === "zh" ? "错误" : "Error";
          terminal.writeln(`\\r\\n[${{errorLabel}}] ${{message.text}}`);
        }}
      }});

      nextSocket.addEventListener("close", () => {{
        if (socket !== nextSocket) {{
          return;
        }}
        stopWsKeepalive();
        socket = null;
        button.disabled = false;
        reconnectButton.disabled = false;
        setStatus(t("disconnected"));
      }});

      nextSocket.addEventListener("error", () => {{
        if (socket !== nextSocket) {{
          return;
        }}
        stopWsKeepalive();
        socket = null;
        button.disabled = false;
        reconnectButton.disabled = false;
        setStatus(t("connectionError"), true);
      }});
    }}

    form.addEventListener("submit", (event) => {{
      event.preventDefault();
      rememberCurrentResourcePassword();
      connectWebTerminal();
    }});

    reconnectButton.addEventListener("click", () => {{
      rememberCurrentResourcePassword();
      connectWebTerminal();
    }});

    terminal.onData((data) => {{
      if (socket && socket.readyState === WebSocket.OPEN) {{
        socket.send(JSON.stringify({{ type: "input", data }}));
      }} else {{
        setStatus(t("disconnected"), true);
      }}
    }});

    window.addEventListener("resize", () => {{
      fitAddon.fit();
      if (socket && socket.readyState === WebSocket.OPEN) {{
        socket.send(JSON.stringify({{
          type: "resize",
          cols: terminal.cols,
          rows: terminal.rows
        }}));
      }}
    }});
    installProfiles();
  </script>
</body>
</html>"""


def run_doctor(config: dict[str, Any]) -> int:
    checks = [
        ("bastion", str(config["bastion_host"]), int(config["bastion_port"])),
    ]
    target = str(config.get("target_command", ""))
    if target.startswith("?"):
        parts = target[1:].split("_")
        if len(parts) >= 2 and parts[1].isdigit():
            checks.append(("target-direct", parts[0], int(parts[1])))

    exit_code = 0
    for name, host, port in checks:
        ok, detail = tcp_probe(host, port, 5.0)
        state = "ok" if ok else "failed"
        if not ok:
            exit_code = 1
        print(f"{name:14} {host}:{port:<5} {state:7} {detail}")
    return exit_code


def run_servers(config: dict[str, Any]) -> None:
    save_default_config()
    local_ssh = LocalSSHListener(config)
    local_ssh.start()
    local_ssh.ready.wait(5)
    if not local_ssh.ready.is_set():
        raise RuntimeError("Local SSH listener did not start.")

    web_host = str(config["web_host"])
    web_port = int(config["web_port"])
    httpd = HelperHTTPServer((web_host, web_port), config)
    browser_host = "127.0.0.1" if web_host in ("", "0.0.0.0", "::") else web_host
    web_url = f"http://{browser_host}:{web_port}"

    print(f"{APP_NAME} v{APP_VERSION} started.")
    print(f"Web terminal: {web_url}")
    print(
        f"Local SSH:    ssh 127.0.0.1 -p {int(config['local_ssh_port'])}"
    )
    print("Press Ctrl+C to stop.")
    if bool(config.get("open_browser_on_start", True)):
        def open_browser() -> None:
            try:
                webbrowser.open(web_url, new=2)
            except Exception as exc:
                print(f"Could not open browser automatically: {exc}", file=sys.stderr)

        browser_timer = threading.Timer(0.5, open_browser)
        browser_timer.daemon = True
        browser_timer.start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        httpd.shutdown()
        local_ssh.stop()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} v{APP_VERSION}",
    )
    parser.add_argument(
        "--config",
        default=str(CONFIG_PATH),
        help="Path to the JSON config file.",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Start the web terminal and local SSH bridge.")
    sub.add_parser("doctor", help="Check TCP connectivity.")
    sub.add_parser("init-config", help="Write the default config if it is missing.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    config_path = Path(args.config)
    if args.command == "init-config":
        save_default_config(config_path)
        print(f"Config ready: {config_path}")
        return 0

    config = load_config(config_path)
    if args.command == "doctor":
        return run_doctor(config)
    if args.command in (None, "serve"):
        run_servers(config)
        return 0
    raise RuntimeError(f"Unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
