#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (高连续性精选版)
=============================================
流程:
  1. 获取 VPN Gate 原始节点 (含 Uptime / Speed / Sessions / Score)
  2. 只保留带 TCP 入口的 SSTP 节点并去重
  3. 读取上一轮线上 data.json 的历史存活 streak，按运行时长分级预筛选
  4. 并发调用检测 Worker，并通过二次复测剔除瞬时通但丢包的抖动节点
  5. 结合双次校验、历史连续存活、在线时长、带宽、负载、延迟与抖动计算 stability_score
  6. 将前 8 个实测低抖动入口优先绑定至高稳定性住宅节点，生成 data.json + index.html + nodes.txt
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://check.xiaoyang1583.dpdns.org/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

PREV_DATA_URL = os.environ.get("PREV_DATA_URL", "https://zf158338-eng.github.io/gate/data.json")
MIN_UPTIME_HOURS = float(os.environ.get("MIN_UPTIME_HOURS", "6"))
MIN_CANDIDATES = int(os.environ.get("MIN_CANDIDATES", "20"))
CONFIRM_CHECKS = max(1, int(os.environ.get("CONFIRM_CHECKS", "2")))
FAST_EDGE_COUNT = int(os.environ.get("FAST_EDGE_COUNT", "8"))

COUNTRY_PRIORITY = {
    "JP": 0, "KR": 1, "US": 2, "SG": 3, "TW": 4,
    "CA": 5, "GB": 6, "DE": 7, "NL": 8, "AU": 9,
}

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# 静态优选域名池（按实测低延迟/低抖动排序，前 8 个优先分配给前排住宅节点）
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        # Top 8 fast low-jitter (~190-230ms)
        "saas.072159.xyz:443,vps.cheng2001.top:8443,baota.us.kg:443,cdn.204910.best:2087,"
        "tt.78607323.xyz:2096,cf.nyanya.moe:2087,api.gzcrtw.com:2087,cf.xreak.top:443,"
        # Remaining 15 backup domains (sorted by measured latency)
        "store.ubi.com:443,serviceshub.samsclub.com:2083,bbs.alipansou.com:443,openai.com:2096,"
        "www.leics.police.uk:2053,ali.nonull.pp.ua:443,cf-cname.xingpingcn.top:443,www.wto.org:2096,"
        "cf.vvhan.com:8443,p.etime.vip:2087,www.giannidelprete.it:2053,www.dbs.com.sg:443,"
        "www.bis.gov:8443,www.sage.com:2083,www.sloomb.com:2087"
    ).split(",")
    if h.strip()
]

# 优选 API 地址配置 (支持逗号分隔多个，可配置在 GitHub Action Secret / Env 中)
OPTIMAL_API = os.environ.get("OPTIMAL_API", "")

NODES_URL = os.environ.get("NODES_URL", "https://zf158338-eng.github.io/gate/nodes.txt")

# ---------------------------------------------------------------------------
# 日志与工具函数
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


def _to_int(val, default=0):
    if val is None or val == "":
        return default
    try:
        return int(float(str(val).strip()))
    except Exception:
        return default


# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败")


def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in (
        "hostname", "ip", "score", "ping", "speed",
        "countrylong", "countryshort", "numvpnsessions",
        "uptime", "totalusers", "openvpn_configdata_base64",
    ):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "score": idx.get("score"),
        "ping": idx.get("ping"),
        "speed": idx.get("speed"),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
        "numvpnsessions": idx.get("numvpnsessions"),
        "uptime": idx.get("uptime"),
        "totalusers": idx.get("totalusers"),
        "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1),
    }

    def _col(fields, key):
        p = pos.get(key)
        return fields[p].strip() if p is not None and p < len(fields) else ""

    rows = []
    for ln in data_lines:
        if ln.startswith("*"):
            continue
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host = _col(fields, "hostname")
        ip = _col(fields, "ip")
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": _col(fields, "countrylong"),
            "country_short": _col(fields, "countryshort"),
            "config_b64": _col(fields, "openvpn_configdata_base64"),
            "score": _to_int(_col(fields, "score"), 0),
            "ping": _to_int(_col(fields, "ping"), 999),
            "speed_mbps": round(_to_int(_col(fields, "speed"), 0) / 1e6, 2),
            "sessions": _to_int(_col(fields, "numvpnsessions"), 0),
            "uptime_h": round(_to_int(_col(fields, "uptime"), 0) / 3600000.0, 2),
            "total_users": _to_int(_col(fields, "totalusers"), 0),
        })
    return rows


def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        sl = {str(k).lower(): v for k, v in s.items()}
        host = str(sl.get("hostname") or sl.get("host") or "").strip()
        ip = str(sl.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(sl.get("countrylong") or sl.get("country_long") or sl.get("country") or "").strip(),
            "country_short": str(sl.get("countryshort") or sl.get("country_short") or "").strip(),
            "config_b64": str(sl.get("openvpn_configdata_base64") or sl.get("config_b64") or "").strip(),
            "score": _to_int(sl.get("score"), 0),
            "ping": _to_int(sl.get("ping"), 999),
            "speed_mbps": round(_to_int(sl.get("speed"), 0) / 1e6, 2),
            "sessions": _to_int(sl.get("numvpnsessions") or sl.get("sessions"), 0),
            "uptime_h": round(_to_int(sl.get("uptime"), 0) / 3600000.0, 2),
            "total_users": _to_int(sl.get("totalusers") or sl.get("total_users"), 0),
        })
    return rows


def fetch_prev_streaks(session):
    """读取上一轮线上 data.json，提取连续存活轮次 streak"""
    if not PREV_DATA_URL:
        return {}
    try:
        resp = session.get(PREV_DATA_URL, timeout=15, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if resp.status_code != 200:
            log("STREAK", f"读取历史数据 HTTP {resp.status_code}，本轮从 0 起算")
            return {}
        prev = resp.json()
        streaks = {}
        for n in prev.get("available") or []:
            h = n.get("host")
            p = n.get("port")
            if h and p:
                streaks[(str(h).lower(), int(p))] = _to_int(n.get("streak"), 1)
        log("STREAK", f"载入上一轮存活记录: {len(streaks)} 个节点")
        return streaks
    except Exception as exc:
        log("STREAK", f"读取历史数据失败 ({exc})，本轮从 0 起算")
        return {}


# ---------------------------------------------------------------------------
# 优选 API 获取与解析
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    """
    拉取优选 API，解析如: 172.66.1.179:443#CF 电信优选 格式的内容
    提取出纯 'IP:端口' (例如 172.66.1.179:443)
    """
    if not api_urls_str.strip():
        return []

    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                lines = resp.text.strip().splitlines()
                count = 0
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    endpoint = line.split("#")[0].strip()
                    if endpoint:
                        if ":" not in endpoint:
                            endpoint = f"{endpoint}:443"
                        endpoints.append(endpoint)
                        count += 1
                log("OPTIMAL API", f"成功从 API 获取到 {count} 个优选端点")
            else:
                log("OPTIMAL API", f"API 返回状态码异常: {resp.status_code}")
        except Exception as e:
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {e}")
    return endpoints


def get_combined_edge_hosts():
    """
    合并静态优选域名与优选 API 端点
    """
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS

    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)

    combined = []
    seen = set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)

    log("EDGE POOL", f"汇总入口地址池: 静态域名 {len(static_hosts)} 个, API 获取 {len(api_hosts)} 个, 合并有效入口共 {len(combined)} 个")
    return combined if combined else EDGE_HOSTS


# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
            "score": r.get("score", 0),
            "ping": r.get("ping", 999),
            "speed_mbps": r.get("speed_mbps", 0.0),
            "sessions": r.get("sessions", 0),
            "uptime_h": r.get("uptime_h", 0.0),
            "total_users": r.get("total_users", 0),
        })
    return nodes


def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


def filter_stable_candidates(nodes, prev_streaks):
    """分级剔除刚开机的短命家宽节点，若候选用量不足则自动降级放宽"""
    if not any(float(n.get("uptime_h") or 0.0) > 0 for n in nodes):
        log("FILTER", "节点均无 uptime 字段，跳过运行时长预筛选")
        return nodes

    tier1 = [
        n for n in nodes
        if float(n.get("uptime_h") or 0.0) >= MIN_UPTIME_HOURS
        or (n["host"].lower(), int(n["port"])) in prev_streaks
    ]
    if len(tier1) >= MIN_CANDIDATES:
        dropped = len(nodes) - len(tier1)
        log("FILTER", f"Tier1 预筛选 (uptime>={MIN_UPTIME_HOURS}h 或历史存活): 保留 {len(tier1)}/{len(nodes)}，过滤短命节点 {dropped} 个")
        return tier1

    tier2 = [
        n for n in nodes
        if float(n.get("uptime_h") or 0.0) >= 1.0
        or (n["host"].lower(), int(n["port"])) in prev_streaks
    ]
    if len(tier2) >= MIN_CANDIDATES:
        dropped = len(nodes) - len(tier2)
        log("FILTER", f"Tier2 降级预筛选 (uptime>=1h 或历史存活): 保留 {len(tier2)}/{len(nodes)}，过滤短命节点 {dropped} 个")
        return tier2

    log("FILTER", f"候选不足 {MIN_CANDIDATES}，放宽保留全部 {len(nodes)} 个去重节点")
    return nodes


# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"
    return "unknown"


def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["success"] = False
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_all(nodes, session):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())

    winners = [r for r in results if r.get("success")]
    if CONFIRM_CHECKS < 2 or not winners:
        for r in winners:
            r["checks_passed"] = 1
            r["confirmed"] = CONFIRM_CHECKS < 2
        return results

    log("CONFIRM CHECK", f"一轮通过 {len(winners)} 个，等待 2s 后进行二轮复测...")
    time.sleep(2)

    round2_map = {}
    with ThreadPoolExecutor(max_workers=min(16, CONCURRENCY)) as pool:
        futures = [pool.submit(check_one, w, session) for w in winners]
        for fut in as_completed(futures):
            r2 = fut.result()
            round2_map[(r2["host"].lower(), int(r2["port"]))] = r2

    for r in winners:
        key = (r["host"].lower(), int(r["port"]))
        r2 = round2_map.get(key)
        if r2 and r2.get("success"):
            r["checks_passed"] = 2
            r["confirmed"] = True
            lat1 = r.get("latency_ms")
            lat2 = r2.get("latency_ms")
            r["check2_ms"] = lat2
            if isinstance(lat1, (int, float)) and isinstance(lat2, (int, float)):
                r["jitter_ms"] = round(abs(lat1 - lat2))
                r["latency_ms"] = round((lat1 + lat2) / 2)
            elif isinstance(lat2, (int, float)):
                r["latency_ms"] = lat2
        else:
            r["checks_passed"] = 1
            r["confirmed"] = False
            r["check2_error"] = r2.get("error") if r2 else "missing"

    res_confirmed = sum(
        1 for r in winners
        if r.get("residential") == "residential" and (r.get("checks_passed") or 0) >= 2
    )
    flaky_count = sum(1 for r in winners if (r.get("checks_passed") or 0) < 2)
    if res_confirmed >= 6:
        for r in winners:
            if (r.get("checks_passed") or 0) < 2:
                r["success"] = False
                r["status"] = "flaky"
        log("CONFIRM CHECK", f"二轮复测完成: 住宅双通过 {res_confirmed} 个，已剔除单轮抖动节点 {flaky_count} 个")
    else:
        log("CONFIRM CHECK", f"二轮住宅仅 {res_confirmed} 个 (<6)，降级保留单轮节点 {flaky_count} 个垫底")

    return results


# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def compute_stability_score(n):
    checks_bonus = 1000.0 if (n.get("checks_passed") or 1) >= 2 else 0.0
    streak_score = min(int(n.get("streak") or 1), 24) * 15.0
    uptime_score = min(float(n.get("uptime_h") or 0.0), 240.0) * 1.5
    speed_score = min(float(n.get("speed_mbps") or 0.0), 300.0) * 0.5
    load_penalty = max(0, int(n.get("sessions") or 0) - 80) * 1.5
    lat_penalty = min(float(n.get("latency_ms") or 5000.0), 8000.0) * 0.02
    jitter_penalty = min(float(n.get("jitter_ms") or 0.0), 3000.0) * 0.03
    return round(
        checks_bonus + streak_score + uptime_score + speed_score
        - load_penalty - lat_penalty - jitter_penalty,
        1,
    )


def build_outputs(results, raw_count, sstp_count, source, prev_streaks=None):
    prev_streaks = prev_streaks or {}
    available = [r for r in results if r.get("success")]
    for n in available:
        key = (n["host"].lower(), int(n["port"]))
        n["streak"] = prev_streaks.get(key, 0) + 1
        n["stability_score"] = compute_stability_score(n)

    available.sort(
        key=lambda n: (
            -float(n.get("stability_score") or 0.0),
            n.get("latency_ms") is None,
            n.get("latency_ms") or 0,
            n["host"],
        )
    )

    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(
            key=lambda n: (
                -float(n.get("stability_score") or 0.0),
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n["host"],
            )
        )
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


def build_nodes_text(data, edge_hosts):
    """
    生成纯节点行版本 (无注释): 每行 = 入口地址#名字$sstp://...
    前 16 个住宅节点优先绑定前 FAST_EDGE_COUNT 个低抖动优选入口
    """
    countries = data["countries"]
    edge = edge_hosts
    fast_edge = edge[:min(FAST_EDGE_COUNT, len(edge))]
    lines = []
    res_idx = 0
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (
            COUNTRY_PRIORITY.get(str(kv[1].get("code") or "?").upper(), 99),
            -int(kv[1].get("count") or 0),
            str(kv[1].get("code") or kv[0]),
        ),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                -float(n.get("stability_score") or 0.0),
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            if res_idx < 16 and fast_edge:
                entry = fast_edge[res_idx % len(fast_edge)]
            else:
                entry = edge[idx % len(edge)]
                idx += 1
            res_idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


def write_outputs(data, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = (
            "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
            "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
            "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>"
        )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_nodes_text(data, edge_hosts))

    return data_path, html_path, nodes_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    prev_streaks = fetch_prev_streaks(session)

    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)
    candidates = filter_stable_candidates(uniq, prev_streaks)

    if MAX_CHECK_NODES > 0:
        candidates = candidates[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}, 送检候选: {len(candidates)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(candidates)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s, 复测轮次 {CONFIRM_CHECKS})")
    t0 = time.time()
    results = check_all(candidates, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"最终可用节点: {len(success)}")
    log("CLOUDFLARE WORKER", f"淘汰/失败节点: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if candidates and not success and len(worker_errors) == len(candidates):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    data = build_outputs(results, raw_count, sstp_count, source, prev_streaks=prev_streaks)
    log("RESULT", f"可用节点: {len(success)} (住宅 {data['stats']['residential_est']}, 机房 {data['stats']['datacenter_est']})")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    edge_hosts = get_combined_edge_hosts()

    data_path, html_path, nodes_path = write_outputs(data, edge_hosts)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (一次配置, 之后自动更新)")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
