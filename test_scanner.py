import socket
import threading

import pytest

import scanner


@pytest.fixture
def open_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def accept():
        try:
            while True:
                c, _ = srv.accept()
                c.sendall(b"HELLO-TEST\n")
                c.close()
        except OSError:
            pass

    threading.Thread(target=accept, daemon=True).start()
    yield port
    srv.close()


def test_detects_open_port(open_port):
    res = scanner.run_scan(["127.0.0.1"], [open_port], timeout=1)
    assert [r["port"] for r in res] == [open_port]


def test_banner_grab(open_port):
    res = scanner.run_scan(["127.0.0.1"], [open_port], banner=True)
    assert "HELLO-TEST" in res[0]["banner"]


def test_closed_port_not_reported():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert scanner.run_scan(["127.0.0.1"], [port], timeout=0.5) == []


def test_parse_ports():
    assert scanner.parse_ports("22,80,100-102") == [22, 80, 100, 101, 102]
    with pytest.raises(ValueError):
        scanner.parse_ports("70000")


def test_scope_blocks_outside(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("127.0.0.0/8\n")
    scope = scanner.load_scope(f)
    scanner.check_scope(["127.0.0.1"], scope)
    with pytest.raises(scanner.ScopeError):
        scanner.check_scope(["8.8.8.8"], scope)


def test_large_range_rejected():
    with pytest.raises(scanner.ScopeError):
        scanner.resolve_targets("10.0.0.0/16")


def test_requires_authorization_flag(tmp_path):
    assert scanner.main(["127.0.0.1"]) == 2


def test_end_to_end_reports(tmp_path, open_port):
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")
    code = scanner.main([
        "127.0.0.1", "-p", str(open_port), "--scope", str(scope),
        "--i-am-authorized", "--json", str(tmp_path / "r.json"),
        "--html", str(tmp_path / "r.html"), "--db", str(tmp_path / "r.db"),
        "--audit-log", str(tmp_path / "audit.log"),
    ])
    assert code == 0
    assert (tmp_path / "r.json").exists()
    assert (tmp_path / "r.html").exists()
    assert "START" in (tmp_path / "audit.log").read_text()
