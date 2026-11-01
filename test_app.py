import app as webapp


def client(tmp_path, monkeypatch):
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")
    monkeypatch.setattr(webapp, "SCOPE_FILE", str(scope))
    monkeypatch.setattr(webapp, "DB_FILE", str(tmp_path / "t.db"))
    monkeypatch.setattr(webapp, "AUDIT_LOG", str(tmp_path / "a.log"))
    return webapp.app.test_client()


def test_home_page(tmp_path, monkeypatch):
    assert b"Authorized Port Scanner" in client(tmp_path, monkeypatch).get("/").data


def test_api_blocks_out_of_scope(tmp_path, monkeypatch):
    r = client(tmp_path, monkeypatch).post(
        "/api/scan", json={"target": "8.8.8.8", "authorized": True})
    assert r.status_code == 403


def test_api_requires_authorization(tmp_path, monkeypatch):
    r = client(tmp_path, monkeypatch).post("/api/scan", json={"target": "127.0.0.1"})
    assert r.status_code == 403


def test_api_scan_ok_and_history(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.post("/api/scan", json={"target": "127.0.0.1", "ports": "1-50", "authorized": True})
    assert r.status_code == 200 and r.json["meta"]["ports_scanned"] == 50
    assert c.get("/api/history").json[0]["target"] == "127.0.0.1"


def test_empty_target_rejected(tmp_path, monkeypatch):
    r = client(tmp_path, monkeypatch).post("/api/scan", json={"target": " ", "authorized": True})
    assert r.status_code == 400
