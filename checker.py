#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio, os, sys, json, re, subprocess, time, socket, gc, glob, base64, ipaddress
from urllib.parse import parse_qs, unquote, urlparse
from datetime import datetime
from enum import Enum

# ====================  НАСТРОЙКИ ====================
MAX_CONCURRENT = 20
TCP_TIMEOUT = 1.0
XRAY_START_WAIT = 0.5
REQ_TIMEOUT = 4
MIN_SUCCESS_RATIO = 0.5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
STRICT_SECURITY_MODE = True

# ====================  КОНФИГУРАЦИЯ ====================
CONFIG_DIR = "config"
SOURCES_FILE = os.path.join(CONFIG_DIR, "sources.json")
DEFAULT_SOURCES_FILE = "default_sources.json"
SITES_CONFIG_FILE = "sites_config.json"
OUTPUT_DIR = "output"
XRAY_PATH = "xray.exe"
BASE_SOCKS_PORT = 30000
VALID_CATEGORIES = ["whitelist_blocked", "regular_blocked", "control"]

# ====================  ЛИМИТЫ БЕЗОПАСНОСТИ ====================
MAX_URL_LENGTH = 8192
MAX_REMARK_LENGTH = 100
MAX_BASE64_SIZE = 65536
MAX_JSON_SIZE = 32768
ALLOWED_PORTS = range(1, 65536)
SAFE_SS_CIPHERS = {
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'chacha20-ietf', 'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305'
}
BLOCKED_TLDS = ('.onion', '.i2p', '.local', '.internal')

# ====================  УТИЛИТЫ ====================

def log(msg, level="INFO"):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}", flush=True)

def format_remark(remark, address, port, idx):
    if not remark or remark == f"{address}:{port}":
        return f" Unknown — #{idx}"
    for sep in [" — #", " | ", " #", " - "]:
        if sep in remark:
            parts = remark.split(sep, 1)
            main = parts[0].strip()
            suffix = parts[1].strip() if len(parts) > 1 else ""
            if suffix and not suffix.isdigit():
                return f"{main}{sep} {suffix}"
            elif suffix.isdigit():
                return f"{main}{sep}{suffix}"
            return main
    return f" {remark[:40]}" + ("..." if len(remark) > 40 else "")

class ProxyType(Enum):
    UNIVERSAL = "as_usual"
    LOCAL = "anti_dushnila_mode"
    CONTROL = "white_spisok"
    DEAD = "DEAD"

# ====================  БЕЗОПАСНОСТЬ ПАРСЕРОВ ====================

def safe_unquote(s, max_passes=3):
    """
    Безопасное декодирование URL с защитой от двойного кодирования.
    Например: %2520 → %20 → пробел
    """
    if not s or not isinstance(s, str):
        return s or ""
    prev = s
    for _ in range(max_passes):
        decoded = unquote(prev)
        if decoded == prev:
            break
        prev = decoded
    return prev


def sanitize_remark(remark, default=""):
    """Очищает remark от спецсимволов и инъекций"""
    if not remark:
        return default
    remark = re.sub(r'[\x00-\x1f\x7f]', '', str(remark))
    if len(remark) > MAX_REMARK_LENGTH:
        remark = remark[:MAX_REMARK_LENGTH] + "..."
    return remark.strip() or default


def validate_address(addr):
    """SSRF защита: блокирует localhost и приватные IP"""
    if not addr or not isinstance(addr, str):
        return False, "Empty address"
    addr = addr.strip().lower()
    
    if addr in ['localhost', '127.0.0.1', '::1', '0.0.0.0', '[::1]']:
        return False, "Loopback blocked"
    
    try:
        ip = ipaddress.ip_address(addr.strip('[]'))
        if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False, f"Private/reserved IP blocked: {ip}"
        return True, None
    except ValueError:
        pass
    
    if not re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', addr):
        return False, f"Invalid hostname: {addr[:30]}"
    
    if any(addr.endswith(tld) for tld in BLOCKED_TLDS):
        return False, f"Blocked TLD: {addr}"
    
    return True, None


def validate_port(port):
    """Проверяет валидность порта"""
    try:
        port = int(port)
        if port not in ALLOWED_PORTS:
            return False, f"Invalid port: {port}"
        return True, port
    except (TypeError, ValueError):
        return False, f"Non-numeric port: {port}"


def validate_uuid(uuid_str):
    """Проверяет формат UUID (32 hex символа)"""
    if not uuid_str:
        return False, "Empty UUID"
    clean = uuid_str.replace('-', '')
    if len(clean) != 32:
        return False, f"Invalid UUID length: {len(clean)}"
    if not re.match(r'^[0-9a-fA-F]+$', clean):
        return False, "UUID contains invalid chars"
    return True, None


def safe_b64decode(data, max_size=MAX_BASE64_SIZE):
    """Безопасное декодирование base64 с ограничением размера"""
    if not data or len(data) > max_size:
        return None
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data)
    except Exception:
        return None


def validate_password(password, min_len=1, max_len=256):
    """Проверяет пароль на валидность"""
    if not password or not isinstance(password, str):
        return False, "Empty password"
    if len(password) < min_len:
        return False, f"Password too short (min {min_len})"
    if len(password) > max_len:
        return False, f"Password too long (max {max_len})"
    return True, None


def validate_url_length(url):
    """Проверяет длину URL"""
    return bool(url and len(url) <= MAX_URL_LENGTH)


# ====================  ФИЛЬТР БЕЗОПАСНОСТИ ====================

def is_proxy_safe(url):
    """Проверяет URL на критические уязвимости конфигурации"""
    if not validate_url_length(url):
        return False, "URL too long"
    
    try:
        if '://' not in url:
            return False, "Invalid URL format"
        
        protocol = url.split('://')[0].lower()
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        def get_param(key, default=''):
            val = params.get(key, [default])[0]
            return unquote(val) if val else default
        
        # Базовая SSRF-проверка для всех протоколов
        if protocol in ['vless', 'trojan', 'hysteria2']:
            m = re.match(rf"{protocol}://[^@]+@([^:]+):(\d+)", url)
            if m:
                addr, port = m.groups()
                ok, msg = validate_address(addr)
                if not ok:
                    return False, msg
                ok, port = validate_port(port)
                if not ok:
                    return False, msg
        
        if protocol == 'vless':
            allow_insecure = get_param('allowInsecure', '0')
            insecure = get_param('insecure', '0')
            sni = get_param('sni', '')
            if (allow_insecure == '1' or insecure == '1') and not sni:
                return False, "VLESS: Insecure mode without SNI"
            if STRICT_SECURITY_MODE and (allow_insecure == '1' or insecure == '1'):
                return False, "VLESS: Insecure mode enabled (Strict)"

        elif protocol == 'hysteria2':
            insecure = get_param('insecure', '0')
            sni = get_param('sni', '')
            if insecure == '1' and not sni:
                return False, "Hysteria2: Insecure mode without SNI"
            if STRICT_SECURITY_MODE and insecure == '1':
                return False, "Hysteria2: Insecure mode enabled (Strict)"

        elif protocol == 'trojan':
            insecure = get_param('insecure', '0')
            sni = get_param('sni', '')
            if insecure == '1' and not sni:
                return False, "Trojan: Insecure mode without SNI"
            if STRICT_SECURITY_MODE and insecure == '1':
                return False, "Trojan: Insecure mode enabled (Strict)"

        elif protocol == 'vmess':
            try:
                b64_part = url.replace('vmess://', '')
                decoded_bytes = safe_b64decode(b64_part)
                if decoded_bytes is None or len(decoded_bytes) > MAX_JSON_SIZE:
                    return False, "VMESS: Invalid/too large Base64"
                config = json.loads(decoded_bytes.decode('utf-8'))
                tls = config.get('tls', '')
                sni = config.get('sni', '')
                insecure = str(config.get('insecure', '0'))
                skip_verify = str(config.get('skip-cert-verify', '0'))
                is_insec = insecure == '1' or skip_verify.lower() == 'true'
                if is_insec and not sni:
                    return False, "VMESS: Insecure without SNI"
                if STRICT_SECURITY_MODE and is_insec:
                    return False, "VMESS: Insecure mode enabled (Strict)"
                if tls == '' or tls == 'none':
                    return False, "VMESS: No TLS encryption"
            except Exception:
                return False, "VMESS: Invalid Base64 or JSON"

        elif protocol == 'ss':
            try:
                m = re.match(r"ss://([^@]+)@", url)
                if m:
                    method_pass = m.group(1)
                    decoded_bytes = safe_b64decode(method_pass)
                    if decoded_bytes:
                        decoded = decoded_bytes.decode('utf-8', errors='ignore')
                        method = decoded.split(':')[0].lower()
                        if method not in SAFE_SS_CIPHERS:
                            return False, f"SS: Unsafe cipher '{method}'"
            except Exception:
                pass

        return True, None

    except Exception as e:
        return False, f"Parsing error: {str(e)[:30]}"


# ====================  РАБОТА С КОНФИГОМ ====================

def load_default_config():
    """Загружает шаблон конфигурации из внешнего JSON-файла"""
    if os.path.exists(DEFAULT_SOURCES_FILE):
        try:
            with open(DEFAULT_SOURCES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log(f" Ошибка чтения {DEFAULT_SOURCES_FILE}: {e}", "WARN")
    
    log(f" Файл {DEFAULT_SOURCES_FILE} не найден, использую встроенный минимум", "WARN")
    return {
        "_meta": {"version": "1.0", "description": "Конфиг источников", "last_updated": ""},
        "blacklist": {"enabled": True, "name": "Blacklist", "description": "", "priority": 1, "urls": []},
        "whitelist": {"enabled": True, "name": "Whitelist", "description": "", "priority": 2, "urls": []},
        "saveme": {"enabled": True, "name": "Saveme", "description": "", "priority": 3, "urls": []},
        "user": {"enabled": True, "name": "User", "description": "", "priority": 4, "urls": []}
    }


def ensure_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    default_cfg = load_default_config()
    
    if not os.path.exists(SOURCES_FILE):
        cfg = default_cfg.copy()
        cfg["_meta"]["last_updated"] = datetime.now().isoformat()
        save_config(cfg)
        log(f" Создан конфиг: {SOURCES_FILE}", "INFO")
        return cfg
    
    cfg = load_config()
    if cfg is None:
        log(" Конфиг повреждён, восстанавливаю", "WARN")
        backup_broken_config()
        cfg = default_cfg.copy()
        cfg["_meta"]["last_updated"] = datetime.now().isoformat()
        save_config(cfg)
    return cfg


def load_config():
    try:
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict) or "_meta" not in cfg:
            return None
        return cfg
    except Exception:
        return None


def save_config(cfg):
    with open(SOURCES_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def backup_broken_config():
    bp = f"{SOURCES_FILE}.broken.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        os.rename(SOURCES_FILE, bp)
        log(f" Бэкап: {bp}", "WARN")
    except Exception:
        pass


def get_enabled_modes(cfg):
    modes = []
    for k in ["blacklist", "whitelist", "saveme", "user"]:
        if k in cfg and cfg[k].get("enabled", True):
            modes.append({
                "key": k,
                "name": cfg[k].get("name", k),
                "desc": cfg[k].get("description", ""),
                "urls": cfg[k].get("urls", []),
                "pri": cfg[k].get("priority", 99)
            })
    return sorted(modes, key=lambda x: x["pri"])


def extract_real_url(url):
    if not url or url.startswith("#"):
        return None
    parsed = urlparse(url.strip())
    if "translate.yandex.ru" in parsed.netloc:
        p = parse_qs(parsed.query)
        r = p.get("url", [None])[0]
        return r.strip() if r else None
    if "vk.com" in parsed.netloc and "/away.php" in parsed.path:
        p = parse_qs(parsed.query)
        r = p.get("to", [None])[0]
        if r:
            r = unquote(r).replace("https://", "").replace("http://", "")
            return f"https://{r}" if not r.startswith("http") else r
    if "t.me" in parsed.netloc and "/iv" in parsed.path:
        p = parse_qs(parsed.query)
        r = p.get("url", [None])[0]
        return r.strip() if r else None
    return url.strip()


# ====================  ЗАГРУЗКА ПРОКСИ ====================

def decode_sub_from_url(url):
    """Загружает подписку из URL"""
    if not validate_url_length(url):
        log(f" URL слишком длинный, пропущен", "WARN")
        return []
    
    log(f" {url[:55]}{'...' if len(url) > 55 else ''}", "DEBUG")
    try:
        import requests
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=20, allow_redirects=True)
        r.raise_for_status()
        content = r.text.strip()
    except Exception as e:
        log(f" requests: {type(e).__name__} → curl", "WARN")
        cmd = f'curl -s -L -m 25 -A "{USER_AGENT}" "{url}"'
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        content = r.stdout.strip() if r.returncode == 0 else ""
    
    if not content:
        return []
    
    valid_prefixes = ("vless://", "hysteria2://", "vmess://", "trojan://", "ss://")
    result = [l.strip() for l in content.split("\n")
              if any(l.strip().startswith(p) for p in valid_prefixes)]
    
    if result:
        log(f" Текст: {len(result)} прокси", "INFO")
    return result


def load_proxies_from_file(filepath):
    """Читает прокси из локального файла"""
    if not os.path.exists(filepath):
        log(f" Файл не найден: {filepath}", "ERROR")
        return []
    content = None
    for enc in ["utf-8", "cp1251", "latin-1", "utf-16"]:
        try:
            with open(filepath, "r", encoding=enc) as f:
                content = f.read().strip()
            break
        except Exception:
            continue
    if not content:
        log(" Не удалось прочитать файл", "ERROR")
        return []
    
    valid_prefixes = ("vless://", "hysteria2://", "vmess://", "trojan://", "ss://")
    result = [l.strip() for l in content.split("\n")
              if l.strip() and not l.strip().startswith("#")
              and any(l.strip().startswith(p) for p in valid_prefixes)]
    
    if result:
        log(f" Загружено из файла: {len(result)} прокси", "INFO")
    return result


# ====================  ОЧИСТКА ====================

def cleanup_workspace():
    log("🧹 Очистка временных файлов и RAM...", "DEBUG")
    tmp_files = glob.glob("tmp_*.json")
    removed = 0
    for f in tmp_files:
        try:
            os.remove(f)
            removed += 1
        except Exception:
            pass
    log(f" Удалено временных файлов: {removed}", "DEBUG")
    gc.collect()


# ====================  ПАРСЕРЫ ПРОТОКОЛОВ ====================

def parse_vless(link):
    if not validate_url_length(link):
        return None
    m = re.match(r"vless://([^@]+)@([^:]+):(\d+)\?([^#]*)(?:#(.*))?", link.strip())
    if not m:
        return None
    uuid, addr, port, query, remark = m.groups()
    
    ok, msg = validate_uuid(uuid)
    if not ok:
        log(f" VLESS: {msg}", "DEBUG")
        return None
    ok, msg = validate_address(addr)
    if not ok:
        log(f" VLESS: {msg}", "DEBUG")
        return None
    ok, port = validate_port(port)
    if not ok:
        log(f" VLESS: {msg}", "DEBUG")
        return None
    
    p = parse_qs(query, keep_blank_values=True)
    def g(k, d=""):
        v = p.get(k, [d])[0]
        return unquote(v) if v else d
    
    sec = g("security", "none")
    sni = g("sni", addr)
    fp = g("fp", "chrome")
    pbk = g("pbk", "")
    sid = g("sid", "")
    spx = g("spx", "")
    type_ = g("type", "tcp")
    host = g("host", "")
    path = g("path", "")
    flow = g("flow", "")
    
    stream = {"network": type_}
    if sec == "reality":
        if not pbk:
            return None
        stream.update({"security": "reality", "realitySettings": {
            "show": False, "publicKey": pbk, "shortId": sid,
            "spiderX": spx, "fingerprint": fp, "serverName": sni
        }})
    elif sec == "tls":
        stream.update({"security": "tls", "tlsSettings": {
            "serverName": sni, "fingerprint": fp, "alpn": ["h2", "http/1.1"]
        }})
    else:
        stream["security"] = "none"
    
    if type_ == "ws" and (path or host):
        stream["wsSettings"] = {"path": path[:2048], "headers": {"Host": host} if host else {}}
    elif type_ == "tcp" and host:
        stream["tcpSettings"] = {"header": {"type": "http", "request": {"headers": {"Host": [host]}}}}
    elif type_ == "grpc":
        stream["grpcSettings"] = {"serviceName": path[:256]}
    
    # ✅ ИСПРАВЛЕНО: используем safe_unquote для защиты от двойного кодирования
    decoded_remark = safe_unquote(remark) if remark else f"{addr}:{port}"
    
    return {
        "protocol": "vless",
        "uuid": uuid, "address": addr, "port": port, "flow": flow,
        "remark": sanitize_remark(decoded_remark, f"{addr}:{port}"),
        "stream": stream
    }


def parse_vmess(link):
    if not validate_url_length(link):
        return None
    try:
        b64_part = link.replace('vmess://', '').strip()
        decoded_bytes = safe_b64decode(b64_part, MAX_BASE64_SIZE)
        if decoded_bytes is None or len(decoded_bytes) > MAX_JSON_SIZE:
            return None
        cfg = json.loads(decoded_bytes.decode('utf-8'))
        if not isinstance(cfg, dict):
            return None
        
        add = cfg.get('add', '')
        port_raw = cfg.get('p', 0)
        id_ = cfg.get('id', '')
        aid = int(cfg.get('aid', 0) or 0)
        net = cfg.get('net', 'tcp')
        type_ = cfg.get('type', 'none')
        host = cfg.get('host', '')
        path = cfg.get('path', '')
        tls = cfg.get('tls', '')
        sni = cfg.get('sni', '') or host
        alpn = cfg.get('alpn', '')
        fp = cfg.get('fp', 'chrome')
        remark = cfg.get('ps', '')
        
        ok, msg = validate_uuid(id_)
        if not ok:
            log(f" VMESS: {msg}", "DEBUG")
            return None
        ok, msg = validate_address(add)
        if not ok:
            log(f" VMESS: {msg}", "DEBUG")
            return None
        ok, port = validate_port(port_raw)
        if not ok:
            log(f" VMESS: {msg}", "DEBUG")
            return None
        
        stream = {"network": net}
        if tls == 'tls':
            tls_settings = {"serverName": sni or add, "fingerprint": fp}
            if alpn:
                tls_settings["alpn"] = [a.strip() for a in alpn.split(',') if a.strip()]
            stream.update({"security": "tls", "tlsSettings": tls_settings})
        else:
            stream["security"] = "none"
        
        if net == 'ws':
            ws_settings = {}
            if path:
                ws_settings["path"] = path[:2048]
            if host:
                ws_settings["headers"] = {"Host": host}
            if ws_settings:
                stream["wsSettings"] = ws_settings
        elif net == 'tcp' and type_ == 'http':
            tcp_settings = {"header": {"type": "http"}}
            if host or path:
                request = {}
                if host:
                    request["headers"] = {"Host": [host]}
                if path:
                    request["path"] = [path[:2048]]
                tcp_settings["request"] = request
            stream["tcpSettings"] = tcp_settings
        elif net == 'grpc':
            stream["grpcSettings"] = {"serviceName": path[:256]}
        
        # VMESS remark из JSON, но на всякий случай тоже декодируем
        decoded_remark = safe_unquote(remark) if remark else f"{add}:{port}"
        
        return {
            "protocol": "vmess",
            "address": add, "port": port, "uuid": id_, "alterId": aid,
            "remark": sanitize_remark(decoded_remark, f"{add}:{port}"),
            "stream": stream
        }
    except Exception as e:
        log(f" VMESS parse error: {e}", "DEBUG")
        return None


def parse_trojan(link):
    if not validate_url_length(link):
        return None
    try:
        m = re.match(r"trojan://([^@]+)@([^:]+):(\d+)\?([^#]*)(?:#(.*))?", link.strip())
        if not m:
            return None
        password, addr, port, query, remark = m.groups()
        
        ok, msg = validate_password(password)
        if not ok:
            log(f" Trojan: {msg}", "DEBUG")
            return None
        ok, msg = validate_address(addr)
        if not ok:
            log(f" Trojan: {msg}", "DEBUG")
            return None
        ok, port = validate_port(port)
        if not ok:
            log(f" Trojan: {msg}", "DEBUG")
            return None
        
        p = parse_qs(query, keep_blank_values=True)
        def g(k, d=""):
            v = p.get(k, [d])[0]
            return unquote(v) if v else d
        
        sni = g("sni", addr)
        alpn = g("alpn", "")
        fp = g("fp", "chrome")
        type_ = g("type", "tcp")
        host = g("host", "")
        path = g("path", "")
        
        tls_settings = {
            "serverName": sni, "fingerprint": fp,
            "alpn": [a.strip() for a in alpn.split(',') if a.strip()] if alpn else ["h2", "http/1.1"]
        }
        stream = {"network": type_, "security": "tls", "tlsSettings": tls_settings}
        
        if type_ == 'ws':
            ws_settings = {}
            if path:
                ws_settings["path"] = path[:2048]
            if host:
                ws_settings["headers"] = {"Host": host}
            if ws_settings:
                stream["wsSettings"] = ws_settings
        elif type_ == 'grpc':
            stream["grpcSettings"] = {"serviceName": path[:256]}
        
        # ✅ ИСПРАВЛЕНО: добавлен safe_unquote для remark
        decoded_remark = safe_unquote(remark) if remark else f"{addr}:{port}"
        
        return {
            "protocol": "trojan",
            "address": addr, "port": port, "password": password,
            "remark": sanitize_remark(decoded_remark, f"{addr}:{port}"),
            "stream": stream
        }
    except Exception as e:
        log(f" Trojan parse error: {e}", "DEBUG")
        return None


def parse_hysteria2(link):
    if not validate_url_length(link):
        return None
    try:
        m = re.match(r"hysteria2://([^@]+)@([^:]+):(\d+)\?([^#]*)(?:#(.*))?", link.strip())
        if not m:
            return None
        password, addr, port, query, remark = m.groups()
        
        ok, msg = validate_password(password)
        if not ok:
            log(f" Hysteria2: {msg}", "DEBUG")
            return None
        ok, msg = validate_address(addr)
        if not ok:
            log(f" Hysteria2: {msg}", "DEBUG")
            return None
        ok, port = validate_port(port)
        if not ok:
            log(f" Hysteria2: {msg}", "DEBUG")
            return None
        
        p = parse_qs(query, keep_blank_values=True)
        def g(k, d=""):
            v = p.get(k, [d])[0]
            return unquote(v) if v else d
        
        sni = g("sni", addr)
        alpn = g("alpn", "")
        insecure = g("insecure", "0")
        obfs = g("obfs", "")
        obfs_password = g("obfs-password", "")
        
        hysteria2_settings = {
            "server": f"{addr}:{port}",
            "password": password,
            "sni": sni,
            "skipCertVerify": insecure == "1"
        }
        if alpn:
            hysteria2_settings["alpn"] = [a.strip() for a in alpn.split(',') if a.strip()]
        if obfs and obfs_password:
            hysteria2_settings["obfs"] = obfs[:64]
            hysteria2_settings["obfsPassword"] = obfs_password[:256]
        
        # ✅ ИСПРАВЛЕНО: добавлен safe_unquote для remark
        decoded_remark = safe_unquote(remark) if remark else f"{addr}:{port}"
        
        return {
            "protocol": "hysteria2",
            "address": addr, "port": port, "password": password, "sni": sni,
            "remark": sanitize_remark(decoded_remark, f"{addr}:{port}"),
            "hysteria2_settings": hysteria2_settings
        }
    except Exception as e:
        log(f" Hysteria2 parse error: {e}", "DEBUG")
        return None


def parse_ss(link):
    if not validate_url_length(link):
        return None
    try:
        m = re.match(r"ss://([^@]+)@([^:]+):(\d+)(?:\?[^#]*)?(?:#(.*))?", link.strip())
        if not m:
            return None
        method_pass, addr, port, remark = m.groups()
        
        ok, msg = validate_address(addr)
        if not ok:
            log(f" SS: {msg}", "DEBUG")
            return None
        ok, port = validate_port(port)
        if not ok:
            log(f" SS: {msg}", "DEBUG")
            return None
        
        decoded_bytes = safe_b64decode(method_pass, MAX_BASE64_SIZE)
        if decoded_bytes is None:
            return None
        try:
            decoded = decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return None
        if ':' not in decoded:
            return None
        method, password = decoded.split(':', 1)
        method = method.strip().lower()
        
        if method not in SAFE_SS_CIPHERS:
            log(f" SS: Unsafe cipher '{method}'", "DEBUG")
            return None
        
        ok, msg = validate_password(password, min_len=1, max_len=256)
        if not ok:
            log(f" SS: {msg}", "DEBUG")
            return None
        
        # ✅ ИСПРАВЛЕНО: используем safe_unquote
        decoded_remark = safe_unquote(remark) if remark else f"{addr}:{port}"
        
        return {
            "protocol": "shadowsocks",
            "address": addr, "port": port, "method": method, "password": password,
            "remark": sanitize_remark(decoded_remark, f"{addr}:{port}")
        }
    except Exception as e:
        log(f" SS parse error: {e}", "DEBUG")
        return None


def parse_proxy_link(link):
    """Универсальный парсер для всех протоколов"""
    link = link.strip()
    if link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    elif link.startswith("hysteria2://"):
        return parse_hysteria2(link)
    elif link.startswith("ss://"):
        return parse_ss(link)
    else:
        log(f" Unknown protocol: {link[:20]}...", "DEBUG")
        return None


# ====================  ГЕНЕРАЦИЯ XRAY-КОНФИГА ====================

def build_xray_outbound(cfg):
    """Генерирует outbound Xray для любого поддерживаемого протокола"""
    protocol = cfg.get("protocol", "vless")
    
    if protocol == "vless":
        return {
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": cfg["address"], "port": cfg["port"],
                "users": [{"id": cfg["uuid"], "encryption": "none", "flow": cfg.get("flow", "")}]
            }]},
            "streamSettings": cfg["stream"],
            "tag": "proxy",
            "mux": {"enabled": False}
        }
    elif protocol == "vmess":
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": cfg["address"], "port": cfg["port"],
                "users": [{"id": cfg["uuid"], "alterId": cfg.get("alterId", 0), "security": "auto"}]
            }]},
            "streamSettings": cfg["stream"],
            "tag": "proxy",
            "mux": {"enabled": False}
        }
    elif protocol == "trojan":
        return {
            "protocol": "trojan",
            "settings": {"servers": [{
                "address": cfg["address"], "port": cfg["port"], "password": cfg["password"]
            }]},
            "streamSettings": cfg["stream"],
            "tag": "proxy",
            "mux": {"enabled": False}
        }
    elif protocol == "hysteria2":
        return {
            "protocol": "hysteria2",
            "settings": cfg["hysteria2_settings"],
            "tag": "proxy"
        }
    elif protocol == "shadowsocks":
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": cfg["address"], "port": cfg["port"],
                "method": cfg["method"], "password": cfg["password"]
            }]},
            "tag": "proxy"
        }
    else:
        log(f" Unsupported protocol: {protocol}", "WARN")
        return None


# ====================  ЯДРО ПРОВЕРКИ ====================

async def tcp_ping_async(host, port, timeout):
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.close()
        await w.wait_closed()
        return True
    except Exception:
        return False


async def curl_async(url, port, timeout):
    """Безопасный curl с валидацией URL"""
    if not url or len(url) > 4096:
        return False
    if not url.startswith(('http://', 'https://')):
        return False
    
    cmd = [
        'curl', '-s', '-o', 'NUL', '-w', '%{http_code}',
        '-m', str(timeout),
        '--socks5-hostname', f'127.0.0.1:{port}',
        '-A', USER_AGENT,
        url
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        return out.decode().strip() in ["200", "204", "301", "302", "304"]
    except Exception:
        return False


def load_sites(filepath):
    default = {
        "whitelist_blocked": {"sites": ["https://github.com"]},
        "regular_blocked": {"sites": ["https://www.youtube.com/generate_204"]},
        "control": {"sites": ["https://www.cloudflare.com/cdn-cgi/trace"]}
    }
    if not os.path.exists(filepath):
        with open(filepath, "w") as f:
            json.dump(default, f, ensure_ascii=False, indent=2)
        return default
    with open(filepath, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    return {k: cfg[k] for k in VALID_CATEGORIES if k in cfg}


async def check_proxy_async(idx, cfg, sites_cfg, sem, results):
    async with sem:
        port = BASE_SOCKS_PORT + idx
        protocol = cfg.get("protocol", "vless").upper()
        display = format_remark(cfg.get('remark', ''), cfg.get('address', ''), cfg.get('port', 0), idx)
        log(f"[{idx:3d}] 🔍 [{protocol}] {display:<40} ({cfg.get('address','?')}:{cfg.get('port','?')})")
        
        if not await tcp_ping_async(cfg["address"], cfg["port"], TCP_TIMEOUT):
            results.append((idx, cfg, {"type": ProxyType.DEAD, "wl": False, "reg": False, "ctrl": False}))
            return
        
        outbound = build_xray_outbound(cfg)
        if outbound is None:
            results.append((idx, cfg, {"type": ProxyType.DEAD, "wl": False, "reg": False, "ctrl": False}))
            return
        
        cfg_json = {
            "log": {"level": "error", "access": "", "error": ""},
            "inbounds": [{
                "port": port, "listen": "127.0.0.1", "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False}
            }],
            "outbounds": [outbound],
            "routing": {"rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
        }
        
        tmp = f"tmp_{port}.json"
        with open(tmp, "w") as f:
            json.dump(cfg_json, f, ensure_ascii=False, indent=2)
        
        si = subprocess.STARTUPINFO() if os.name == "nt" else None
        if os.name == "nt":
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        cf = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        
        proc = await asyncio.create_subprocess_exec(
            XRAY_PATH, "-config", tmp,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            startupinfo=si,
            creationflags=cf
        )
        
        t0 = time.monotonic()
        ok = False
        while time.monotonic() - t0 < XRAY_START_WAIT:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=0.15)
                w.close()
                await w.wait_closed()
                ok = True
                break
            except Exception:
                await asyncio.sleep(0.03)
        
        if not ok:
            proc.kill()
            await proc.wait()
            if os.path.exists(tmp):
                os.remove(tmp)
            results.append((idx, cfg, {"type": ProxyType.DEAD, "wl": False, "reg": False, "ctrl": False}))
            return
        
        async def test_cat(k):
            sites = sites_cfg[k]["sites"]
            tasks = [curl_async(s, port, REQ_TIMEOUT) for s in sites]
            res = await asyncio.gather(*tasks, return_exceptions=True)
            return (sum(1 for r in res if r is True) / len(sites)) >= MIN_SUCCESS_RATIO if sites else False
        
        wl, reg, ctrl = await asyncio.gather(
            test_cat("whitelist_blocked"),
            test_cat("regular_blocked"),
            test_cat("control")
        )
        
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except Exception:
            proc.kill()
        if os.path.exists(tmp):
            os.remove(tmp)
        
        t = (ProxyType.UNIVERSAL if reg and ctrl
             else ProxyType.LOCAL if wl and not reg
             else ProxyType.CONTROL if ctrl
             else ProxyType.DEAD)
        results.append((idx, cfg, {"type": t, "wl": wl, "reg": reg, "ctrl": ctrl}))


# ====================  МЕНЮ ====================

def show_main_menu(config):
    modes = get_enabled_modes(config)
    print("\n" + "═" * 70)
    print(" Proxy Checker v7.2 — Multi-Protocol + Secure + Safety Filter")
    print("═" * 70)
    print(f" Конфиг: {SOURCES_FILE}")
    print(f" Обновлено: {config.get('_meta', {}).get('last_updated', 'неизвестно')[:19]}")
    print("\n РЕЖИМЫ (из sources.json):")
    for i, mode in enumerate(modes, 1):
        print(f"\n  {i}. {mode['name']}")
        print(f"     {mode['desc']}")
        print(f"      Источников: {len([u for u in mode['urls'] if not u.startswith('#')])}")
    print(f"\n  {len(modes)+1}.  Загрузить из локального файла")
    print(f"  {len(modes)+2}.   Редактировать sources.json")
    print(f"  {len(modes)+3}.  Открыть папку config/")
    print(f"  {len(modes)+4}.  Сбросить конфиг к дефолту")
    print(f"  {len(modes)+5}.  Выход")
    print("\n" + "─" * 70)
    while True:
        choice = input(f" Ваш выбор [1-{len(modes)+5}]: ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(modes):
                return run_check_from_json(modes[idx-1]["key"], modes[idx-1]["urls"])
            elif idx == len(modes) + 1:
                filepath = input(" Введите путь к файлу с прокси: ").strip()
                if not filepath:
                    print(" Пустой путь")
                    continue
                proxies = load_proxies_from_file(filepath)
                if not proxies:
                    log(" Файл пуст или не содержит поддерживаемых протоколов", "ERROR")
                    input("⏎ Нажмите Enter...")
                    return show_main_menu(config)
                
                safe_proxies = []
                skipped_count = 0
                for p in proxies:
                    is_safe, reason = is_proxy_safe(p)
                    if is_safe:
                        safe_proxies.append(p)
                    else:
                        skipped_count += 1
                
                if skipped_count > 0:
                    log(f" Отфильтровано {skipped_count} опасных/невалидных прокси", "WARN")
                
                if not safe_proxies:
                    log(" Все прокси отфильтрованы как опасные", "ERROR")
                    input("⏎ Нажмите Enter...")
                    return show_main_menu(config)

                configs = [parse_proxy_link(p) for p in safe_proxies]
                configs = [c for c in configs if c]
                
                if not configs:
                    log(" Не распарсилось ни одной ссылки", "ERROR")
                    input("⏎ Нажмите Enter...")
                    return show_main_menu(config)
                
                for c in configs:
                    c["original_link"] = next((p for p in safe_proxies if parse_proxy_link(p) == c), "")
                return ("local_file", os.path.basename(filepath), configs)
                
            elif idx == len(modes) + 2:
                edit_config_file()
                config = ensure_config()
                print(" Конфиг обновлён")
                input("⏎ Enter...")
                return show_main_menu(config)
            elif idx == len(modes) + 3:
                open_folder(CONFIG_DIR)
                input("⏎ Enter...")
            elif idx == len(modes) + 4:
                if confirm(" Сбросить sources.json?"):
                    backup_broken_config()
                    config = load_default_config()
                    config["_meta"]["last_updated"] = datetime.now().isoformat()
                    save_config(config)
                    log("🔄 Сброшено", "INFO")
                    input("⏎ Enter...")
                    return show_main_menu(config)
            elif idx == len(modes) + 5:
                return ("exit", None, None)
        print(" Неверный ввод")


def edit_config_file():
    fp = os.path.abspath(SOURCES_FILE)
    try:
        if os.name == "nt":
            os.startfile(fp)
        elif sys.platform == "darwin":
            subprocess.run(["open", fp])
        else:
            for ed in ["nano", "vim", "code", "notepad"]:
                if subprocess.run(["which", ed], capture_output=True).returncode == 0:
                    subprocess.run([ed, fp])
                    return
            subprocess.run(["xdg-open", fp])
        log(f" Открыт: {fp}", "INFO")
    except Exception as e:
        log(f" Не удалось открыть: {e}", "WARN")
        print(f"💡 Путь: {fp}")


def open_folder(path):
    try:
        if os.name == "nt":
            os.startfile(os.path.abspath(path))
        elif sys.platform == "darwin":
            subprocess.run(["open", os.path.abspath(path)])
        else:
            subprocess.run(["xdg-open", os.path.abspath(path)])
    except Exception:
        print(f" {os.path.abspath(path)}")


def confirm(prompt):
    while True:
        r = input(f"{prompt} [y/N]: ").strip().lower()
        if r in ["y", "yes", "да", "д"]:
            return True
        if r in ["", "n", "no", "нет", "н"]:
            return False


# ====================  ОСНОВНАЯ ЛОГИКА ====================

def run_check_from_json(mode_key, urls):
    clean_urls = [extract_real_url(u) for u in urls]
    clean_urls = [u for u in clean_urls if u and not u.startswith("#")]
    if not clean_urls:
        log(f" В режиме '{mode_key}' нет активных источников", "ERROR")
        input("⏎ Enter...")
        config = ensure_config()
        return show_main_menu(config)
    
    all_proxies = []
    for url in clean_urls:
        proxies = decode_sub_from_url(url)
        all_proxies.extend(proxies)
    
    if not all_proxies:
        log(" Не найдено валидных ссылок", "ERROR")
        input("⏎ Enter...")
        config = ensure_config()
        return show_main_menu(config)

    log(" Проверка конфигураций на безопасность...", "INFO")
    safe_proxies = []
    skipped_count = 0
    for p in all_proxies:
        is_safe, reason = is_proxy_safe(p)
        if is_safe:
            safe_proxies.append(p)
        else:
            skipped_count += 1
    
    if skipped_count > 0:
        log(f" Отфильтровано {skipped_count} опасных/некорректных прокси", "WARN")
    
    if not safe_proxies:
        log(" Все прокси отфильтрованы как опасные", "ERROR")
        input("⏎ Enter...")
        config = ensure_config()
        return show_main_menu(config)

    configs = [parse_proxy_link(p) for p in safe_proxies]
    configs = [c for c in configs if c]
    
    if not configs:
        log(" Не распарсилось ни одной ссылки после фильтрации", "ERROR")
        input("⏎ Enter...")
        config = ensure_config()
        return show_main_menu(config)
    
    for c in configs:
        c["original_link"] = next((p for p in safe_proxies if parse_proxy_link(p) == c), "")
    
    return (mode_key, "json_batch", configs)


async def main_async(mode_key_or_name, source_type, configs):
    default_cfg = load_default_config()
    mode_name = (mode_key_or_name if source_type == "local_file"
                 else default_cfg.get(mode_key_or_name, {}).get("name", mode_key_or_name))
    log(f" Proxy Checker v7.2 — РЕЖИМ: {mode_name}")
    log(f" Потоков: {MAX_CONCURRENT} | TCP: {TCP_TIMEOUT}с | Curl: {REQ_TIMEOUT}с")
    
    proto_stats = {}
    for c in configs:
        p = c.get("protocol", "unknown")
        proto_stats[p] = proto_stats.get(p, 0) + 1
    log(f" Протоколы: {proto_stats}")
    
    if not os.path.exists(XRAY_PATH):
        log(" xray.exe не найден", "ERROR")
        return
    
    sites = load_sites(SITES_CONFIG_FILE)
    log(f" Проверка {len(configs)} прокси...\n")
    
    results = []
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [check_proxy_async(i+1, cfg, sites, sem, results) for i, cfg in enumerate(configs)]
    
    start = time.time()
    await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.time() - start
    speed = len(configs) / (elapsed / 60) if elapsed > 0 else 0
    log(f"\n⏱ Готово за {elapsed:.1f} сек | {speed:.0f} прокси/мин")
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = "lf" if source_type == "local_file" else mode_key_or_name[:2]
    
    classified = {t: [] for t in ProxyType}
    for _, cfg, res in results:
        classified[res["type"]].append(cfg)
    
    for t in ProxyType:
        fn = f"{OUTPUT_DIR}/{prefix}_{t.value}_{ts}.txt"
        with open(fn, "w", encoding="utf-8") as f:
            for c in classified[t]:
                original = c.get("original_link", "")
                original = original.replace('\n', '').replace('\r', '')
                f.write(original + "\n")
        log(f" {t.value}: {len(classified[t])} → {fn}")
    
    total = len(results)
    stats = {t.value: len(classified[t]) for t in ProxyType}
    print(f"\n ИТОГО: {total}")
    print(f"    UNIVERSAL: {stats['as_usual']}")
    print(f"    LOCAL:    {stats['anti_dushnila_mode']}")
    print(f"    CONTROL:  {stats['white_spisok']}")
    print(f"    DEAD:     {stats['DEAD']}")
    log(f"\n Импортируйте UNIVERSAL/LOCAL в клиент!")
    
    cleanup_workspace()


# ==================== ЗАПУСК ====================
if __name__ == "__main__":
    try:
        config = ensure_config()
        result = show_main_menu(config)
        if result[0] == "exit":
            log(" Выход")
            sys.exit(0)
        asyncio.run(main_async(result[0], result[1], result[2]))
    except KeyboardInterrupt:
        log("\n Стоп", "WARN")
        cleanup_workspace()
    except Exception as e:
        log(f" {e}", "ERROR")
        import traceback
        traceback.print_exc()