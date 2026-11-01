#!/usr/bin/env python3
"""Authorized Port Scanner.

A TCP connect scanner that refuses to touch anything outside an explicit,
written scope file. Intended for lab environments and systems you own or
have written permission to test.

Features: scope allowlist, authorization flag, audit log, threaded scanning,
optional banner grabbing, risk flags, JSON / HTML reports, SQLite history.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import html
import ipaddress
import json
import socket
import sqlite3
import sys
from pathlib import Path

MAX_HOSTS = 256
MAX_THREADS = 200
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
             995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
             27017]
RISKY = {
    21: "FTP sends credentials in clear text",
    23: "Telnet is unencrypted; use SSH",
    135: "Windows RPC exposed",
    139: "NetBIOS exposed",
    445: "SMB exposed; common attack target",
    1433: "SQL Server exposed",
    3306: "MySQL exposed",
    3389: "RDP exposed; enforce MFA/VPN",
    5432: "PostgreSQL exposed",
    5900: "VNC exposed",
    6379: "Redis often has no auth",
    27017: "MongoDB exposed",
}


class ScopeError(Exception):
    pass


def load_scope(path):
    """Read allowed IPs / CIDRs / hostnames from a file (one per line, # comments)."""
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"Scope file not found: {path}")
    nets = []
    for line in p.read_text().splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            try:
                ip = socket.gethostbyname(line)
                nets.append(ipaddress.ip_network(ip + "/32"))
            except OSError:
                print(f"[warn] cannot resolve scope entry: {line}", file=sys.stderr)
    if not nets:
        raise ScopeError("Scope file is empty; nothing is authorized.")
    return nets


def resolve_targets(target):
    """Turn an IP, CIDR or hostname into a list of IPs (capped)."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > MAX_HOSTS:
            raise ScopeError(f"Target covers {net.num_addresses} hosts; max is {MAX_HOSTS}.")
        hosts = list(net.hosts()) or [net.network_address]
        return [str(h) for h in hosts]
    except ValueError:
        try:
            return [socket.gethostbyname(target)]
        except OSError as e:
            raise ScopeError(f"Cannot resolve {target}: {e}")


def check_scope(ips, scope):
    """Abort unless every IP is inside the authorized scope."""
    bad = [ip for ip in ips if not any(ipaddress.ip_address(ip) in n for n in scope)]
    if bad:
        raise ScopeError(f"Out of authorized scope: {', '.join(bad[:5])}"
                         + (" ..." if len(bad) > 5 else ""))


def parse_ports(spec):
    if spec == "top":
        return list(TOP_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            ports.update(range(a, b + 1))
        elif part:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    return sorted(ports)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(ip, port, timeout=1.0, banner=False):
    """TCP connect scan of one port. Returns a result dict if open, else None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            info = ""
            if banner:
                try:
                    s.settimeout(1.0)
                    info = s.recv(128).decode(errors="replace").strip()
                except OSError:
                    pass
            return {"ip": ip, "port": port, "service": service_name(port),
                    "banner": info, "risk": RISKY.get(port, "")}
    except OSError:
        return None


def run_scan(ips, ports, timeout=1.0, threads=100, banner=False):
    threads = min(threads, MAX_THREADS)
    results = []
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(scan_port, ip, p, timeout, banner) for ip in ips for p in ports]
        for f in cf.as_completed(futs):
            r = f.result()
            if r:
                results.append(r)
    return sorted(results, key=lambda r: (ipaddress.ip_address(r["ip"]), r["port"]))


def audit(logfile, message):
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    with open(logfile, "a") as f:
        f.write(f"{stamp} {message}\n")


def save_json(path, meta, results):
    Path(path).write_text(json.dumps({"meta": meta, "results": results}, indent=2))


def save_html(path, meta, results):
    rows = "".join(
        f"<tr><td>{html.escape(r['ip'])}</td><td>{r['port']}</td>"
        f"<td>{html.escape(r['service'])}</td><td>{html.escape(r['banner'])}</td>"
        f"<td class='{'risk' if r['risk'] else ''}'>{html.escape(r['risk'])}</td></tr>"
        for r in results)
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Port Scan Report</title>
<style>body{{font-family:sans-serif;margin:1rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px;text-align:left}}th{{background:#eee}}.risk{{color:#b00020;font-weight:bold}}
.wrap{{overflow-x:auto}}</style></head><body>
<h1>Port Scan Report</h1>
<p><b>Target:</b> {html.escape(meta['target'])}<br><b>Started:</b> {meta['started']}<br>
<b>Hosts:</b> {meta['hosts']} &nbsp; <b>Ports scanned:</b> {meta['ports_scanned']} &nbsp;
<b>Open found:</b> {len(results)}</p>
<div class="wrap"><table><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th><th>Risk note</th></tr>
{rows or '<tr><td colspan=5>No open ports found.</td></tr>'}</table></div>
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")


def save_db(path, meta, results):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY, target TEXT, started TEXT, hosts INTEGER, ports_scanned INTEGER)""")
    con.execute("""CREATE TABLE IF NOT EXISTS results(
        scan_id INTEGER, ip TEXT, port INTEGER, service TEXT, banner TEXT, risk TEXT)""")
    cur = con.execute("INSERT INTO scans(target,started,hosts,ports_scanned) VALUES(?,?,?,?)",
                      (meta["target"], meta["started"], meta["hosts"], meta["ports_scanned"]))
    con.executemany("INSERT INTO results VALUES(?,?,?,?,?,?)",
                    [(cur.lastrowid, r["ip"], r["port"], r["service"], r["banner"], r["risk"])
                     for r in results])
    con.commit()
    con.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Authorized TCP port scanner")
    ap.add_argument("target", help="IP, CIDR (max /24) or hostname")
    ap.add_argument("-p", "--ports", default="top", help="'top', '1-1024', or '22,80,443'")
    ap.add_argument("--scope", default="authorized_targets.txt", help="allowlist file")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="confirm you have permission to scan the target")
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--threads", type=int, default=100)
    ap.add_argument("--banner", action="store_true", help="grab service banners")
    ap.add_argument("--json", help="write JSON report")
    ap.add_argument("--html", help="write HTML report")
    ap.add_argument("--db", help="save results to SQLite file")
    ap.add_argument("--audit-log", default="audit.log")
    a = ap.parse_args(argv)

    if not a.i_am_authorized:
        print("Refusing to scan: pass --i-am-authorized to confirm you have permission.")
        return 2
    try:
        scope = load_scope(a.scope)
        ips = resolve_targets(a.target)
        check_scope(ips, scope)
        ports = parse_ports(a.ports)
    except (ScopeError, ValueError) as e:
        audit(a.audit_log, f"BLOCKED target={a.target} reason={e}")
        print(f"Blocked: {e}")
        return 1

    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    audit(a.audit_log, f"START target={a.target} hosts={len(ips)} ports={len(ports)}")
    results = run_scan(ips, ports, a.timeout, a.threads, a.banner)
    audit(a.audit_log, f"END target={a.target} open={len(results)}")

    meta = {"target": a.target, "started": started, "hosts": len(ips),
            "ports_scanned": len(ports)}
    print(f"{'HOST':<16}{'PORT':<7}{'SERVICE':<12}RISK")
    for r in results:
        print(f"{r['ip']:<16}{r['port']:<7}{r['service']:<12}{r['risk']}")
    print(f"\n{len(results)} open port(s) across {len(ips)} host(s).")

    if a.json:
        save_json(a.json, meta, results)
    if a.html:
        save_html(a.html, meta, results)
    if a.db:
        save_db(a.db, meta, results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
