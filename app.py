"""Web front end + JSON API for the authorized port scanner.

Run locally:  python app.py   then open http://127.0.0.1:5000
Deploy:       gunicorn app:app --timeout 120
Scope is enforced by authorized_targets.txt exactly like the CLI.
"""
import datetime as dt
import os
import sqlite3
import time

from flask import Flask, jsonify, render_template, request

import scanner

app = Flask(__name__)
SCOPE_FILE = os.environ.get("SCOPE_FILE", "authorized_targets.txt")
DB_FILE = os.environ.get("SCAN_DB", "scans.db")
AUDIT_LOG = os.environ.get("AUDIT_LOG", "audit.log")
MAX_PORTS = 1024



def do_scan(target, ports_spec, banner, authorized):
    """Validate scope, run the scan, store it. Raises ScopeError/ValueError."""
    target = (target or "").strip()
    if not authorized:
        raise scanner.ScopeError("Confirm that you are authorized to scan this target.")
    if not target:
        raise ValueError("Enter a target.")
    try:
        scope = scanner.load_scope(SCOPE_FILE)
        ips = scanner.resolve_targets(target)
        scanner.check_scope(ips, scope)
        ports = scanner.parse_ports(ports_spec or "top")
        if len(ports) > MAX_PORTS:
            raise ValueError(f"At most {MAX_PORTS} ports per scan.")
    except (scanner.ScopeError, ValueError) as e:
        scanner.audit(AUDIT_LOG, f"BLOCKED web target={target} reason={e}")
        raise
    t0 = time.monotonic()
    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    scanner.audit(AUDIT_LOG, f"START web target={target} hosts={len(ips)} ports={len(ports)}")
    results = scanner.run_scan(ips, ports, timeout=1.0, threads=100, banner=banner)
    scanner.audit(AUDIT_LOG, f"END web target={target} open={len(results)}")
    meta = {"target": target, "started": started, "hosts": len(ips),
            "ports_scanned": len(ports),
            "duration": round(time.monotonic() - t0, 1)}
    scanner.save_db(DB_FILE, meta, results)
    return meta, results, ports


def scope_entries():
    try:
        lines = open(SCOPE_FILE).read().splitlines()
    except OSError:
        return []
    return [l.split("#")[0].strip() for l in lines if l.split("#")[0].strip()]


def recent_history(limit=5):
    try:
        con = sqlite3.connect(DB_FILE)
        rows = con.execute(
            "SELECT target, started, ports_scanned FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        con.close()
        return rows
    except sqlite3.Error:
        return []


@app.route("/", methods=["GET", "POST"])
def index():
    ctx = {"target": "127.0.0.1", "ports": "top", "banner": False, "meta": None,
           "results": [], "error": None, "grid": [], "risky": 0, "payload": None}
    if request.method == "POST":
        ctx["target"] = request.form.get("target", "")
        ctx["ports"] = request.form.get("ports", "top") or "top"
        ctx["banner"] = bool(request.form.get("banner"))
        try:
            meta, results, ports = do_scan(
                ctx["target"], ctx["ports"], ctx["banner"], bool(request.form.get("auth")))
            results = sorted(results, key=lambda r: (not r["risk"], r["port"]))
            state = {r["port"]: ("risky" if r["risk"] else "open") for r in results}
            ctx.update(meta=meta, results=results, risky=sum(1 for r in results if r["risk"]),
                       grid=[{"p": p, "s": state.get(p, "closed")} for p in ports],
                       payload={"meta": meta, "results": results})
        except (scanner.ScopeError, ValueError) as e:
            ctx["error"] = str(e)
    ctx["history"] = recent_history()
    ctx["scope_entries"] = scope_entries()
    return render_template("index.html", **ctx)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    try:
        meta, results, _ = do_scan(data.get("target"), data.get("ports", "top"),
                                bool(data.get("banner")), bool(data.get("authorized")))
    except scanner.ScopeError as e:
        return jsonify(error=str(e)), 403
    except ValueError as e:
        return jsonify(error=str(e)), 400
    return jsonify(meta=meta, results=results)


@app.route("/api/history")
def api_history():
    rows = recent_history(20)
    return jsonify([{"target": r[0], "started": r[1], "ports_scanned": r[2]} for r in rows])


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
