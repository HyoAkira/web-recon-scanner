import argparse
import csv
import datetime
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


class Toa:
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url if "://" in url else f"https://{url}")
        self.domain = self.parsed.hostname or url
        self.results = {
            "url": self.url,
            "domain": self.domain,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "whois": None,
            "dns": {},
            "http_headers": {},
            "security_headers": {},
            "cors": {},
            "tech_fingerprint": {},
            "cve_matches": [],
            "tls": {},
            "robots": None,
            "sitemap": None,
            "subdomains": [],
            "third_party": [],
            "endpoints": [],
            "wayback_urls": [],
            "active_scan": {},
            "summary_stats": {},
            "risk_summary": {},
            "external_tools": {},
            "notes": [],
        }

    def _run_command(self, args):
        tool = args[0]
        if not shutil.which(tool):
            return {
                "ok": False,
                "error": f"{tool} not found on PATH",
                "stdout": "",
                "stderr": "",
            }

        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "error": "" if completed.returncode == 0 else f"exit code {completed.returncode}",
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }

    def _fetch_url(self, url, method="GET"):
        try:
            request = Request(url, method=method)
            with urlopen(request, timeout=10) as response:
                return {
                    "ok": True,
                    "status": response.status,
                    "headers": dict(response.getheaders()),
                    "body": response.read().decode("utf-8", errors="replace"),
                    "error": "",
                }
        except Exception as exc:
            return {
                "ok": False,
                "status": None,
                "headers": {},
                "body": "",
                "error": str(exc),
            }

    def _save_raw_output(self, path, stdout, stderr):
        try:
            with open(path, "w", encoding="utf-8") as handle:
                if stdout:
                    handle.write(stdout)
                if stderr:
                    handle.write("\n\n[stderr]\n")
                    handle.write(stderr)
        except Exception as exc:
            self.results["notes"].append(f"raw output save error: {exc}")

    def whois(self):
        result = self._run_command(["whois", self.domain])
        self.results["whois"] = result
        return result

    def dns(self):
        records = ["A", "AAAA", "MX", "TXT", "NS", "SOA"]
        for record in records:
            result = self._run_command(["dig", "+short", self.domain, record])
            self.results["dns"][record] = result
        return self.results["dns"]

    def http_headers(self):
        headers = {}
        response = self._fetch_url(self.url)
        if response["ok"]:
            headers = response["headers"]
        else:
            self.results["notes"].append(f"http headers error: {response['error']}")
        self.results["http_headers"] = headers
        return headers

    def security_headers(self):
        headers = {k.lower(): v for k, v in (self.results.get("http_headers") or {}).items()}
        expected = [
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
        missing = [name for name in expected if name not in headers]
        present = {name: headers.get(name, "") for name in expected if name in headers}
        self.results["security_headers"] = {
            "missing": missing,
            "present": present,
        }
        return self.results["security_headers"]

    def cors_policy(self):
        headers = {k.lower(): v for k, v in (self.results.get("http_headers") or {}).items()}
        self.results["cors"] = {
            "access_control_allow_origin": headers.get("access-control-allow-origin", ""),
            "access_control_allow_credentials": headers.get("access-control-allow-credentials", ""),
            "access_control_allow_methods": headers.get("access-control-allow-methods", ""),
            "access_control_allow_headers": headers.get("access-control-allow-headers", ""),
        }
        return self.results["cors"]

    def tech_fingerprint(self):
        headers = {k.lower(): v for k, v in (self.results.get("http_headers") or {}).items()}
        self.results["tech_fingerprint"] = {
            "server": headers.get("server", ""),
            "x_powered_by": headers.get("x-powered-by", ""),
            "via": headers.get("via", ""),
        }
        return self.results["tech_fingerprint"]

    def cve_lookup(self):
        tech = " ".join((self.results.get("tech_fingerprint") or {}).values()).lower()
        mapping = {
            "nginx": [
                {
                    "cve": "CVE-2021-23017",
                    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017",
                }
            ],
            "apache": [
                {
                    "cve": "CVE-2021-41773",
                    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773",
                }
            ],
            "iis": [
                {
                    "cve": "CVE-2021-31166",
                    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31166",
                }
            ],
        }

        matches = []
        for keyword, cves in mapping.items():
            if keyword in tech:
                for item in cves:
                    matches.append({
                        "keyword": keyword,
                        "cve": item["cve"],
                        "url": item["url"],
                        "note": "hint only; verify version impact",
                    })

        self.results["cve_matches"] = matches
        return matches

    def tls_info(self):
        if self.parsed.scheme != "https":
            self.results["notes"].append("tls info skipped: non-https url")
            return {}

        info = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    days_until_expiry = self._days_until_expiry(cert.get("notAfter"))
                    info = {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial_number": cert.get("serialNumber"),
                        "cipher": ssock.cipher(),
                        "days_until_expiry": days_until_expiry,
                    }
        except Exception as exc:
            self.results["notes"].append(f"tls info error: {exc}")

        self.results["tls"] = info
        return info

    def _days_until_expiry(self, not_after):
        if not not_after:
            return None
        try:
            normalized = " ".join(not_after.split())
            expires = datetime.datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z")
            return (expires - datetime.datetime.utcnow()).days
        except Exception as exc:
            self.results["notes"].append(f"tls expiry parse error: {exc}")
            return None

    def fetch_robots(self):
        robots_url = f"{self.parsed.scheme}://{self.domain}/robots.txt"
        response = self._fetch_url(robots_url)
        if response["ok"]:
            self.results["robots"] = response["body"]
        else:
            self.results["notes"].append(f"robots error: {response['error']}")
        return self.results["robots"]

    def fetch_sitemap(self):
        sitemap_url = f"{self.parsed.scheme}://{self.domain}/sitemap.xml"
        response = self._fetch_url(sitemap_url)
        if response["ok"]:
            self.results["sitemap"] = response["body"]
        else:
            self.results["notes"].append(f"sitemap error: {response['error']}")
        return self.results["sitemap"]

    def fetch_homepage(self):
        response = self._fetch_url(self.url)
        if not response["ok"]:
            self.results["notes"].append(f"homepage error: {response['error']}")
            return ""
        return response["body"]

    def _normalize_url(self, candidate):
        if candidate.startswith("http://") or candidate.startswith("https://"):
            return candidate
        return urljoin(self.url, candidate)

    def _is_same_domain(self, candidate):
        parsed = urlparse(candidate)
        if not parsed.hostname:
            return True
        if parsed.hostname == self.domain:
            return True
        return parsed.hostname.endswith(f".{self.domain}")

    def _extract_urls(self, text):
        urls = set()
        for match in re.findall(r"(?:src|href)=[\"']([^\"']+)", text, flags=re.IGNORECASE):
            urls.add(self._normalize_url(match))
        return sorted(urls)

    def _extract_endpoints(self, text):
        endpoints = set()
        for match in re.findall(r"/[^\"'\s)]+", text):
            if match.startswith("//"):
                continue
            if len(match) < 2:
                continue
            endpoints.add(match)
        return sorted(endpoints)

    def _extract_inline_scripts(self, text):
        scripts = []
        for match in re.findall(r"<script[^>]*>(.*?)</script>", text, flags=re.IGNORECASE | re.DOTALL):
            if match.strip():
                scripts.append(match)
        return scripts

    def _extract_data_attributes(self, text):
        endpoints = set()
        for match in re.findall(r"data-[a-z0-9_-]+=[\"']([^\"']+)[\"']", text, flags=re.IGNORECASE):
            if match.startswith("/"):
                endpoints.add(match)
        return endpoints

    def _extract_inline_json(self, text):
        endpoints = set()
        for match in re.findall(r"\"(/[^\"']+)\"", text):
            if match.startswith("//"):
                continue
            if len(match) < 2:
                continue
            endpoints.add(match)
        return endpoints

    def _extract_api_patterns(self, text):
        endpoints = set()
        for match in re.findall(r"/api/[a-zA-Z0-9_\-./]+", text):
            endpoints.add(match)
        return endpoints

    def _extract_from_robots(self, text):
        endpoints = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key in {"disallow", "allow", "sitemap"} and value.startswith("/"):
                endpoints.add(value)
        return endpoints

    def _extract_from_sitemap(self, text):
        endpoints = set()
        for match in re.findall(r"<loc>([^<]+)</loc>", text, flags=re.IGNORECASE):
            path = urlparse(match).path
            if path:
                endpoints.add(path)
        return endpoints

    def discover_endpoints(self, max_js=5, js_any_domain=False):
        homepage = self.fetch_homepage()
        urls = self._extract_urls(homepage)
        endpoints = set(self._extract_endpoints(homepage))

        for inline_script in self._extract_inline_scripts(homepage):
            endpoints.update(self._extract_endpoints(inline_script))
            endpoints.update(self._extract_inline_json(inline_script))
            endpoints.update(self._extract_api_patterns(inline_script))

        endpoints.update(self._extract_data_attributes(homepage))
        endpoints.update(self._extract_inline_json(homepage))
        endpoints.update(self._extract_api_patterns(homepage))

        js_urls = [u for u in urls if u.endswith(".js")]
        if not js_any_domain:
            js_urls = [u for u in js_urls if self._is_same_domain(u)]
        js_urls = js_urls[:max_js]
        for js_url in js_urls:
            response = self._fetch_url(js_url)
            if not response["ok"]:
                continue
            endpoints.update(self._extract_endpoints(response["body"]))
            endpoints.update(self._extract_inline_json(response["body"]))
            endpoints.update(self._extract_api_patterns(response["body"]))

        robots_text = self.results.get("robots") or ""
        sitemap_text = self.results.get("sitemap") or ""
        endpoints.update(self._extract_from_robots(robots_text))
        endpoints.update(self._extract_from_sitemap(sitemap_text))

        self.results["endpoints"] = sorted(endpoints)

        third_party = set()
        for found in urls:
            domain = urlparse(found).hostname
            if not domain:
                continue
            if domain == self.domain or domain.endswith(f".{self.domain}"):
                continue
            third_party.add(domain)

        self.results["third_party"] = sorted(third_party)
        return self.results["endpoints"]

    def ct_subdomains(self):
        ct_url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        response = self._fetch_url(ct_url)
        if not response["ok"]:
            self.results["notes"].append(f"ct log error: {response['error']}")
            return []
        try:
            data = json.loads(response["body"])
        except json.JSONDecodeError as exc:
            self.results["notes"].append(f"ct log json error: {exc}")
            return []

        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for item in name_value.split("\n"):
                item = item.strip().lower()
                if item and item.endswith(self.domain):
                    subdomains.add(item)

        self.results["subdomains"] = sorted(subdomains)
        return self.results["subdomains"]

    def wayback_urls(self, max_results=200):
        wayback_url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={self.domain}/*&output=json&fl=original&collapse=urlkey"
        )
        response = self._fetch_url(wayback_url)
        if not response["ok"]:
            self.results["notes"].append(f"wayback error: {response['error']}")
            return []
        try:
            data = json.loads(response["body"])
        except json.JSONDecodeError as exc:
            self.results["notes"].append(f"wayback json error: {exc}")
            return []

        urls = [row[0] for row in data[1:] if row]
        self.results["wayback_urls"] = urls[:max_results]
        return self.results["wayback_urls"]

    def run_gau(self, output_dir=None, base_name=None):
        result = self._run_command(["gau", self.domain])
        output_path = None
        if output_dir and base_name:
            output_path = os.path.join(output_dir, f"{base_name}_gau.txt")
            self._save_raw_output(output_path, result.get("stdout", ""), result.get("stderr", ""))

        urls = []
        if result.get("stdout"):
            urls = sorted({line.strip() for line in result["stdout"].splitlines() if line.strip()})

        self.results["external_tools"]["gau"] = {
            "ok": result.get("ok"),
            "error": result.get("error"),
            "count": len(urls),
            "sample": urls[:50],
            "raw_output": output_path,
        }
        return urls

    def run_theharvester(self, output_dir=None, base_name=None):
        result = self._run_command(["theHarvester", "-d", self.domain, "-b", "all"])
        output_path = None
        if output_dir and base_name:
            output_path = os.path.join(output_dir, f"{base_name}_theharvester.txt")
            self._save_raw_output(output_path, result.get("stdout", ""), result.get("stderr", ""))

        emails = []
        hosts = []
        if result.get("stdout"):
            emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+", result["stdout"])))
            hosts = sorted({
                match for match in re.findall(r"[a-zA-Z0-9._-]+\.%s" % re.escape(self.domain), result["stdout"])
            })

        self.results["external_tools"]["theHarvester"] = {
            "ok": result.get("ok"),
            "error": result.get("error"),
            "emails": emails[:50],
            "hosts": hosts[:100],
            "raw_output": output_path,
        }
        return {"emails": emails, "hosts": hosts}

    def run_whatweb(self, output_dir=None, base_name=None):
        result = self._run_command(["whatweb", self.url])
        output_path = None
        if output_dir and base_name:
            output_path = os.path.join(output_dir, f"{base_name}_whatweb.txt")
            self._save_raw_output(output_path, result.get("stdout", ""), result.get("stderr", ""))

        summary = result.get("stdout", "")
        self.results["external_tools"]["whatweb"] = {
            "ok": result.get("ok"),
            "error": result.get("error"),
            "summary": summary.strip(),
            "raw_output": output_path,
        }
        return summary

    def active_scan(self, ports):
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((self.domain, port), timeout=2):
                    open_ports.append(port)
            except Exception:
                continue
        self.results["active_scan"] = {"ports": ports, "open": open_ports, "services": []}
        return self.results["active_scan"]

    def nmap_scan(self, ports, full_scan=False):
        if not shutil.which("nmap"):
            self.results["notes"].append("nmap not found on PATH")
            return self.active_scan(ports)

        if full_scan:
            port_arg = "-p-"
        else:
            port_arg = f"-p {ports}"

        command = ["nmap", "-sV", "--open", "-oX", "-", port_arg, self.domain]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            self.results["notes"].append(f"nmap error: {completed.stderr.strip()}")
            return self.active_scan(ports)

        services = []
        open_ports = []
        try:
            root = ET.fromstring(completed.stdout)
            for host in root.findall("host"):
                for port in host.findall("ports/port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    portid = port.get("portid")
                    protocol = port.get("protocol")
                    service = port.find("service")
                    entry = {
                        "port": int(portid) if portid and portid.isdigit() else portid,
                        "protocol": protocol,
                        "state": "open",
                        "name": service.get("name") if service is not None else "",
                        "product": service.get("product") if service is not None else "",
                        "version": service.get("version") if service is not None else "",
                        "extrainfo": service.get("extrainfo") if service is not None else "",
                    }
                    services.append(entry)
                    if isinstance(entry["port"], int):
                        open_ports.append(entry["port"])
        except Exception as exc:
            self.results["notes"].append(f"nmap parse error: {exc}")
            return self.active_scan(ports)

        self.results["active_scan"] = {
            "ports": ports,
            "open": sorted(set(open_ports)),
            "services": services,
            "tool": "nmap",
        }
        return self.results["active_scan"]

    def summary_stats(self):
        self.results["summary_stats"] = {
            "subdomains": len(self.results.get("subdomains") or []),
            "third_party": len(self.results.get("third_party") or []),
            "endpoints": len(self.results.get("endpoints") or []),
            "wayback_urls": len(self.results.get("wayback_urls") or []),
            "open_ports": len(self.results.get("active_scan", {}).get("open", []) or []),
            "gau_urls": self.results.get("external_tools", {}).get("gau", {}).get("count", 0),
        }
        return self.results["summary_stats"]

    def risk_summary(self):
        summary = {"findings": []}
        security = self.results.get("security_headers") or {}
        missing = security.get("missing", [])
        if missing:
            summary["findings"].append({
                "type": "security_headers_missing",
                "details": missing,
                "severity": "low",
            })

        cors = self.results.get("cors") or {}
        if cors.get("access_control_allow_origin") == "*":
            summary["findings"].append({
                "type": "cors_wildcard",
                "details": "Access-Control-Allow-Origin: *",
                "severity": "medium",
            })

        days_until_expiry = (self.results.get("tls") or {}).get("days_until_expiry")
        if isinstance(days_until_expiry, int):
            if days_until_expiry < 0:
                summary["findings"].append({
                    "type": "tls_expired",
                    "details": f"expired {abs(days_until_expiry)} days ago",
                    "severity": "high",
                })
            elif days_until_expiry <= 30:
                summary["findings"].append({
                    "type": "tls_expiring_soon",
                    "details": f"expires in {days_until_expiry} days",
                    "severity": "medium",
                })

        if self.results.get("active_scan", {}).get("open"):
            summary["findings"].append({
                "type": "open_ports",
                "details": self.results["active_scan"].get("open"),
                "severity": "info",
            })

        severity_counts = {"low": 0, "medium": 0, "high": 0, "info": 0}
        for finding in summary["findings"]:
            severity = finding.get("severity")
            if severity in severity_counts:
                severity_counts[severity] += 1
        summary["severity_counts"] = severity_counts

        self.results["risk_summary"] = summary
        return summary

    def run(
        self,
        active=False,
        ports=None,
        max_js=5,
        max_wayback=200,
        js_any_domain=False,
        full_scan=False,
        use_nmap=True,
        output_dir=None,
        base_name=None,
    ):
        self.whois()
        self.dns()
        self.http_headers()
        self.security_headers()
        self.cors_policy()
        self.tech_fingerprint()
        self.cve_lookup()
        self.tls_info()
        self.fetch_robots()
        self.fetch_sitemap()
        self.ct_subdomains()
        self.discover_endpoints(max_js=max_js, js_any_domain=js_any_domain)
        self.wayback_urls(max_results=max_wayback)
        self.run_gau(output_dir=output_dir, base_name=base_name)
        self.run_theharvester(output_dir=output_dir, base_name=base_name)
        self.run_whatweb(output_dir=output_dir, base_name=base_name)
        if active and ports:
            if use_nmap:
                self.nmap_scan(ports, full_scan=full_scan)
            else:
                self.active_scan(ports)
        self.summary_stats()
        self.risk_summary()
        return self.results


def render_text_report(results):
    lines = []
    lines.append("Threat Surface Report")
    lines.append(f"URL: {results.get('url')}")
    lines.append(f"Domain: {results.get('domain')}")
    lines.append(f"Timestamp: {results.get('timestamp')}")
    lines.append("")

    lines.append("WHOIS:")
    whois = results.get("whois") or {}
    lines.append(whois.get("stdout", ""))
    if whois.get("stderr"):
        lines.append("WHOIS errors:")
        lines.append(whois.get("stderr"))
    lines.append("")

    lines.append("DNS:")
    for record, data in (results.get("dns") or {}).items():
        lines.append(f"{record}: {data.get('stdout', '')}")
    lines.append("")

    lines.append("HTTP Headers:")
    for key, value in (results.get("http_headers") or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")

    lines.append("Security Headers:")
    security = results.get("security_headers") or {}
    lines.append(f"missing: {', '.join(security.get('missing', []))}")
    for key, value in (security.get("present") or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")

    lines.append("CORS:")
    cors = results.get("cors") or {}
    for key, value in cors.items():
        lines.append(f"{key}: {value}")
    lines.append("")

    lines.append("Tech Fingerprint:")
    tech = results.get("tech_fingerprint") or {}
    for key, value in tech.items():
        lines.append(f"{key}: {value}")
    lines.append("")

    lines.append("CVE Hints:")
    cves = results.get("cve_matches") or []
    if cves:
        for item in cves:
            lines.append(f"{item.get('cve')}: {item.get('url')} ({item.get('note')})")
    else:
        lines.append("none")
    lines.append("")

    lines.append("TLS:")
    for key, value in (results.get("tls") or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")

    lines.append("robots.txt:")
    lines.append(results.get("robots") or "")
    lines.append("")

    lines.append("sitemap.xml:")
    lines.append(results.get("sitemap") or "")
    lines.append("")

    lines.append("Subdomains (CT log):")
    lines.extend(results.get("subdomains") or [])
    lines.append("")

    lines.append("Third-party Domains:")
    lines.extend(results.get("third_party") or [])
    lines.append("")

    lines.append("Discovered Endpoints:")
    lines.extend(results.get("endpoints") or [])
    lines.append("")

    lines.append("Wayback URLs:")
    lines.extend(results.get("wayback_urls") or [])
    lines.append("")

    lines.append("External Tools:")
    external = results.get("external_tools") or {}
    for tool, data in external.items():
        lines.append(f"{tool}: ok={data.get('ok')} error={data.get('error')} raw={data.get('raw_output')}")
    lines.append("")

    lines.append("Active Scan:")
    active = results.get("active_scan") or {}
    if active:
        lines.append(f"ports: {active.get('ports', [])}")
        lines.append(f"open: {active.get('open', [])}")
        for svc in active.get("services", []):
            lines.append(
                f"service: {svc.get('port')}/{svc.get('protocol')} {svc.get('name')}"
                f" {svc.get('product')} {svc.get('version')} {svc.get('extrainfo')}"
            )
    else:
        lines.append("skipped")
    lines.append("")

    lines.append("Risk Summary:")
    summary = results.get("risk_summary") or {}
    for finding in summary.get("findings", []):
        lines.append(f"- {finding.get('type')}: {finding.get('details')} (sev: {finding.get('severity')})")
    if not summary.get("findings"):
        lines.append("no notable findings")
    lines.append(f"severity counts: {summary.get('severity_counts', {})}")
    lines.append("")

    lines.append("Summary Stats:")
    stats = results.get("summary_stats") or {}
    for key, value in stats.items():
        lines.append(f"{key}: {value}")
    lines.append("")

    if results.get("notes"):
        lines.append("Notes:")
        lines.extend(results.get("notes"))

    return "\n".join(lines).strip() + "\n"


def normalize_target_url(raw_url):
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    return cleaned


def load_targets(url, targets_file):
    targets = []
    if url:
        normalized = normalize_target_url(url)
        if normalized:
            targets.append(normalized)
    if targets_file:
        try:
            with open(targets_file, "r", encoding="utf-8") as handle:
                for line in handle:
                    normalized = normalize_target_url(line)
                    if normalized:
                        targets.append(normalized)
        except FileNotFoundError:
            raise SystemExit(f"targets file not found: {targets_file}")
    return targets


def load_allowlist(allowlist_file):
    if not allowlist_file:
        return []
    allowlist = []
    try:
        with open(allowlist_file, "r", encoding="utf-8") as handle:
            for line in handle:
                entry = line.strip().lower()
                if entry and not entry.startswith("#"):
                    allowlist.append(entry)
    except FileNotFoundError:
        raise SystemExit(f"allowlist file not found: {allowlist_file}")
    return allowlist


def is_allowed(domain, allowlist):
    if not allowlist:
        return True
    for entry in allowlist:
        if domain == entry or domain.endswith(f".{entry}"):
            return True
    return False


def write_outputs(results, output_dir, base_name, json_path, report_path):
    os.makedirs(output_dir, exist_ok=True)
    report_output = report_path or os.path.join(output_dir, f"{base_name}.txt")
    json_output = json_path or os.path.join(output_dir, f"{base_name}.json")

    with open(report_output, "w", encoding="utf-8") as handle:
        handle.write(render_text_report(results))

    with open(json_output, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    return report_output, json_output


def append_csv(results, csv_path):
    stats = results.get("summary_stats", {})
    severity = (results.get("risk_summary") or {}).get("severity_counts", {})
    row = {
        "url": results.get("url"),
        "domain": results.get("domain"),
        "timestamp": results.get("timestamp"),
        "subdomains": stats.get("subdomains"),
        "third_party": stats.get("third_party"),
        "endpoints": stats.get("endpoints"),
        "wayback_urls": stats.get("wayback_urls"),
        "open_ports": stats.get("open_ports"),
        "severity_low": severity.get("low"),
        "severity_medium": severity.get("medium"),
        "severity_high": severity.get("high"),
        "severity_info": severity.get("info"),
    }

    file_exists = os.path.exists(csv_path)
    with open(csv_path, "a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=row.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Threat surface discovery (passive) by URL")
    parser.add_argument("url", nargs="?", help="Target URL, e.g. https://example.com")
    parser.add_argument("--targets-file", help="File with one target per line")
    parser.add_argument("--allowlist-file", help="Allowed domains list (one per line)")
    parser.add_argument("--output-dir", default="runs", help="Directory for report outputs")
    parser.add_argument("--report", help="Report output path (single-target only)")
    parser.add_argument("--json", help="JSON output path (single-target only)")
    parser.add_argument("--csv", help="Append results to CSV file")
    parser.add_argument("--active", action="store_true", help="Enable active scan (allowed targets only)")
    parser.add_argument("--ports", default="80,443,22,21,25,110,143,3306,5432")
    parser.add_argument("--full-ports", action="store_true", help="Scan full port range with nmap")
    parser.add_argument("--no-nmap", action="store_true", help="Disable nmap and use socket scan")
    parser.add_argument("--max-js", type=int, default=5)
    parser.add_argument("--max-wayback", type=int, default=200)
    parser.add_argument("--js-any-domain", action="store_true", help="Allow JS fetch from third-party domains")
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    targets = load_targets(args.url, args.targets_file)
    if not targets:
        raise SystemExit("no targets provided")

    allowlist = load_allowlist(args.allowlist_file)
    active = args.active
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.output_dir, timestamp)
    os.makedirs(run_dir, exist_ok=True)

    for target in targets:
        toa = Toa(target)
        if not is_allowed(toa.domain, allowlist):
            toa.results["notes"].append("skipped: domain not in allowlist")
            results = toa.results
        else:
            results = toa.run(
                active=active,
                ports=ports,
                max_js=args.max_js,
                max_wayback=args.max_wayback,
                js_any_domain=args.js_any_domain,
                full_scan=args.full_ports,
                use_nmap=not args.no_nmap,
                output_dir=run_dir,
                base_name=toa.domain.replace(".", "_"),
            )

        base_name = toa.domain.replace(".", "_")
        report_path = args.report if len(targets) == 1 else None
        json_path = args.json if len(targets) == 1 else None
        write_outputs(results, run_dir, base_name, json_path, report_path)

        if args.csv:
            append_csv(results, args.csv)


if __name__ == "__main__":
    main()
    