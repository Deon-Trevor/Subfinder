from __future__ import annotations

import json
import re
import urllib.request
import urllib.parse

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_hostname(v: str) -> bool:
    v = v.strip().lower().rstrip(".")
    if not v or len(v) > 253 or "." not in v:
        return False
    return all(_LABEL.fullmatch(l) for l in v.split("."))


class ThcAdapter:
    name = "thc"

    def __init__(self, database=None, timeout: int = 10) -> None:
        self.database = database
        self.timeout = timeout

    def fetch(self, apex: str) -> list[str]:
        url = f"https://ip.thc.org/api/v1/subdomains?domain={urllib.parse.quote(apex)}"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        hosts: list[str] = []
        if isinstance(payload, dict):
            for key in ("subdomains", "data", "result"):
                val = payload.get(key)
                if isinstance(val, list):
                    for x in val:
                        if isinstance(x, str) and _is_hostname(x):
                            hosts.append(x.lower().rstrip("."))
                    break
        elif isinstance(payload, list):
            for x in payload:
                if isinstance(x, str) and _is_hostname(x):
                    hosts.append(x.lower().rstrip("."))
        return list(dict.fromkeys(hosts))


class SubMdAdapter:
    name = "submd"

    def __init__(self, database=None, timeout: int = 10) -> None:
        self.database = database
        self.timeout = timeout

    def fetch(self, apex: str) -> list[str]:
        url = f"https://sub.md/api/v1/search?domain={urllib.parse.quote(apex)}"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        hosts = []
        if isinstance(payload, dict):
            for key in ("subdomains", "data", "results"):
                val = payload.get(key)
                if isinstance(val, list):
                    for x in val:
                        if isinstance(x, str) and _is_hostname(x):
                            hosts.append(x.lower().rstrip("."))
                        elif isinstance(x, dict):
                            n = x.get("subdomain") or x.get("host")
                            if isinstance(n, str) and _is_hostname(n):
                                hosts.append(n.lower().rstrip("."))
                    break
        elif isinstance(payload, list):
            for x in payload:
                if isinstance(x, str) and _is_hostname(x):
                    hosts.append(x.lower().rstrip("."))
        return list(dict.fromkeys(hosts))


class RapidDnsAdapter:
    name = "rapiddns"

    def __init__(self, database=None, timeout: int = 10) -> None:
        self.database = database
        self.timeout = timeout

    def fetch(self, apex: str) -> list[str]:
        url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(apex)}?full=1"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        # RapidDNS returns HTML table or JSON; extract hostnames via regex fallback
        hosts = re.findall(r"([a-z0-9-]+\." + re.escape(apex) + r")", text, re.IGNORECASE)
        # Also try JSON
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                for v in payload.values():
                    if isinstance(v, list):
                        for x in v:
                            if isinstance(x, str) and _is_hostname(x):
                                hosts.append(x)
            elif isinstance(payload, list):
                for x in payload:
                    if isinstance(x, str) and _is_hostname(x):
                        hosts.append(x)
        except json.JSONDecodeError:
            pass
        uniq = []
        seen = set()
        for h in hosts:
            h = h.lower().rstrip(".")
            if h.endswith(f".{apex}") or h == apex:
                if h not in seen:
                    seen.add(h)
                    uniq.append(h)
        return uniq


class HackerTargetAdapter:
    name = "hackertarget"

    def __init__(self, database=None, timeout: int = 10) -> None:
        self.database = database
        self.timeout = timeout

    def fetch(self, apex: str) -> list[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(apex)}"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        hosts: list[str] = []
        for line in text.splitlines():
            # Format: "host,ip"
            host = line.split(",")[0].strip().lower().rstrip(".")
            if host and _is_hostname(host) and (host == apex or host.endswith(f".{apex}")):
                hosts.append(host)
        return list(dict.fromkeys(hosts))


class SiteDossierAdapter:
    name = "sitedossier"

    def __init__(self, database=None, timeout: int = 10) -> None:
        self.database = database
        self.timeout = timeout

    def fetch(self, apex: str) -> list[str]:
        url = f"http://www.sitedossier.com/parentdomain/{urllib.parse.quote(apex)}"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        hosts = re.findall(r"([a-z0-9-]+\." + re.escape(apex) + r")", text, re.IGNORECASE)
        uniq = []
        seen = set()
        for h in hosts:
            h = h.lower().rstrip(".")
            if h not in seen and _is_hostname(h):
                seen.add(h)
                uniq.append(h)
        return uniq


class CrtNameAdapter:
    name = "crtname"

    def __init__(self, database=None, timeout: int = 10) -> None:
        self.database = database
        self.timeout = timeout

    def fetch(self, apex: str) -> list[str]:
        # crt.name is external per-apex backfill; guard against self-loop later
        url = f"https://crt.name/api/search?domain={urllib.parse.quote(apex)}"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        hosts = []
        if isinstance(payload, list):
            for x in payload:
                if isinstance(x, str) and _is_hostname(x):
                    hosts.append(x.lower().rstrip("."))
                elif isinstance(x, dict):
                    for key in ("name", "subdomain", "host"):
                        v = x.get(key)
                        if isinstance(v, str) and _is_hostname(v):
                            hosts.append(v.lower().rstrip("."))
                            break
        elif isinstance(payload, dict):
            for key in ("subdomains", "hosts", "data"):
                val = payload.get(key)
                if isinstance(val, list):
                    for x in val:
                        if isinstance(x, str) and _is_hostname(x):
                            hosts.append(x.lower().rstrip("."))
                    break
        return list(dict.fromkeys([h for h in hosts if h == apex or h.endswith(f".{apex}")]))
