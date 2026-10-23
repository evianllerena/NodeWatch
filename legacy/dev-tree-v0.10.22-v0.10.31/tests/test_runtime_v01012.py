"""v0.10.12: bundled interpreter, NodeWatchBackend.exe host, Exit NodeWatch."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- Exit endpoint -------------------------------------------------------------


@pytest.fixture()
def exit_recorder(monkeypatch):
    from app.modules.system import router as system_router

    called = threading.Event()
    monkeypatch.setattr(system_router, "EXIT_DELAY_SECONDS", 0.0)
    monkeypatch.setattr(system_router, "_shutdown_hook", called.set)
    return called


def test_exit_requires_request_token(exit_recorder):
    from app.main import app

    client = TestClient(app, base_url="http://127.0.0.1")
    r = client.post("/api/system/exit")
    assert r.status_code == 403
    r = client.post("/api/system/exit", headers={"X-NodeWatch-Request": "wrong"})
    assert r.status_code == 403
    assert not exit_recorder.wait(0.3)


def test_exit_responds_then_stops_backend(exit_recorder):
    from app.core.security import WRITE_REQUEST_TOKEN
    from app.main import app

    client = TestClient(app, base_url="http://127.0.0.1")
    r = client.post("/api/system/exit", headers={"X-NodeWatch-Request": WRITE_REQUEST_TOKEN}, json={})
    assert r.status_code == 200
    assert r.json()["stopping"] is True
    assert exit_recorder.wait(5), "shutdown hook was not scheduled"


def test_exit_get_is_not_routed(exit_recorder):
    from app.core.security import WRITE_REQUEST_TOKEN
    from app.main import app

    client = TestClient(app, base_url="http://127.0.0.1")
    r = client.get("/api/system/exit", headers={"X-NodeWatch-Request": WRITE_REQUEST_TOKEN})
    assert r.status_code == 405
    assert not exit_recorder.wait(0.3)


def test_launcher_request_shutdown_uses_running_server(monkeypatch):
    import app.launcher as launcher

    assert launcher.request_shutdown() is False  # no server in the test process

    class FakeServer:
        should_exit = False

    fake = FakeServer()
    monkeypatch.setattr(launcher, "_SERVER", fake)
    assert launcher.request_shutdown() is True
    assert fake.should_exit is True


def test_default_shutdown_prefers_clean_uvicorn_stop(monkeypatch):
    import app.launcher as launcher
    from app.modules.system import router as system_router

    calls = []
    monkeypatch.setattr(launcher, "request_shutdown", lambda: calls.append("clean") or True)
    monkeypatch.setattr(system_router.os, "_exit", lambda code: calls.append(("exit", code)))
    monkeypatch.setattr(system_router, "EXIT_FORCE_AFTER_SECONDS", 3600.0)
    system_router._stop_backend_process()
    assert calls == ["clean"]  # hard exit only as a delayed backstop


def test_default_shutdown_hard_exits_without_server(monkeypatch):
    import app.launcher as launcher
    from app.modules.system import router as system_router

    calls = []
    monkeypatch.setattr(launcher, "request_shutdown", lambda: False)
    monkeypatch.setattr(system_router.os, "_exit", lambda code: calls.append(code))
    system_router._stop_backend_process()
    assert calls == [0]


def test_exit_button_in_support_card():
    html = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
    support = html.split('data-ui="Settings &amp; Support › Simple support workflow"', 1)[1].split("</section>", 1)[0]
    assert 'id="settingsExitApp"' in support and "Exit NodeWatch" in support
    js = (ROOT / "app/static/modules/settings.js").read_text(encoding="utf-8")
    assert "addEventListener('click', exitNodeWatch)" in js
    fn = js.split("async function exitNodeWatch()", 1)[1].split("\nasync function ", 1)[0]
    assert "/api/system/exit" in fn
    assert "NodeWatch has stopped." in fn and "You can close this tab." in fn


# --- tools/stage_runtime.py ----------------------------------------------------


def _fake_pbs_archive(path: Path, extra: dict[str, bytes] | None = None) -> None:
    files = {
        "python/python.exe": b"exe",
        "python/pythonw.exe": b"exe",
        "python/python312.dll": b"dll",
        "python/python3.dll": b"dll",
        "python/vcruntime140.dll": b"dll",
        "python/Lib/os.py": b"# os",
        "python/Lib/encodings/__init__.py": b"",
        "python/Lib/venv/__init__.py": b"",
        "python/Lib/venv/scripts/nt/python.exe": b"exe",
        "python/Lib/ensurepip/__init__.py": b"",
        "python/Lib/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl": b"whl",
        "python/Lib/site-packages/README.txt": b"readme",
        "python/Lib/site-packages/pip/__init__.py": b"",
        "python/Lib/site-packages/pip-26.2.1.dist-info/METADATA": b"",
        "python/Lib/idlelib/idle.py": b"",
        "python/Lib/tkinter/__init__.py": b"",
        "python/Lib/turtledemo/a.py": b"",
        "python/Lib/turtle.py": b"",
        "python/Lib/lib2to3/a.py": b"",
        "python/Lib/unittest/test/test_x.py": b"",
        "python/Lib/__pycache__/os.cpython-312.pyc": b"",
        "python/DLLs/_ssl.pyd": b"",
        "python/DLLs/_socket.pyd": b"",
        "python/DLLs/libssl-3-x64.dll": b"",
        "python/DLLs/_tkinter.pyd": b"",
        "python/DLLs/tcl86t.dll": b"",
        "python/DLLs/_testcapi.pyd": b"",
        "python/DLLs/_ctypes_test.pyd": b"",
        "python/tcl/tcl8.6/init.tcl": b"",
        "python/include/Python.h": b"",
        "python/libs/python312.lib": b"",
        "python/python312.pdb": b"",
    }
    files.update(extra or {})
    with tarfile.open(path, "w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_stage_runtime_trims_and_keeps_what_venv_needs(tmp_path):
    stage = _load(ROOT / "tools/stage_runtime.py", "stage_runtime_under_test")
    archive = tmp_path / "pbs.tar.gz"
    _fake_pbs_archive(archive)
    dest = tmp_path / "runtime" / "python"
    count, _ = stage.stage(archive, dest, stage.sha256(archive))
    staged = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    assert count == len(staged)
    for kept in (
        "python.exe",
        "python312.dll",
        "Lib/os.py",
        "Lib/venv/scripts/nt/python.exe",
        "Lib/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl",
        "Lib/site-packages/README.txt",
        "DLLs/_ssl.pyd",
    ):
        assert kept in staged
    for dropped in ("idlelib", "tkinter", "turtledemo", "lib2to3", "__pycache__", "tcl/", "include/", "libs/"):
        assert not any(dropped in name for name in staged), dropped
    assert not any(name.startswith("Lib/site-packages/pip") for name in staged)
    assert not any(name.endswith((".pdb", ".pyc")) or "/_test" in name for name in staged)
    assert "Lib/turtle.py" not in staged and "Lib/unittest/test/test_x.py" not in staged
    assert "DLLs/_tkinter.pyd" not in staged and "DLLs/_ctypes_test.pyd" not in staged


def test_stage_runtime_rejects_bad_hash_and_unsafe_members(tmp_path):
    stage = _load(ROOT / "tools/stage_runtime.py", "stage_runtime_under_test2")
    archive = tmp_path / "pbs.tar.gz"
    _fake_pbs_archive(archive)
    with pytest.raises(SystemExit):
        stage.stage(archive, tmp_path / "a" / "python", "0" * 64)
    evil = tmp_path / "evil.tar.gz"
    _fake_pbs_archive(evil, {"python/../escape.txt": b"x"})
    with pytest.raises(SystemExit):
        stage.stage(evil, tmp_path / "b" / "python", None)
    assert not (tmp_path / "b" / "escape.txt").exists()
    # Never wipes a folder that is not a staged runtime.
    other = tmp_path / "c" / "python"
    other.mkdir(parents=True)
    (other / "keep.txt").write_text("x")
    with pytest.raises(SystemExit):
        stage.stage(archive, other, None)
    assert (other / "keep.txt").exists()


def test_runtime_folder_is_git_ignored():
    assert "/runtime/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


# --- release/generate_integrity.py -----------------------------------------------


def test_integrity_lists_bundled_interpreter_files(tmp_path, monkeypatch):
    gi = _load(ROOT / "release/generate_integrity.py", "generate_integrity_under_test")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("x = 1\n")
    (tmp_path / "requirements.txt").write_text("fastapi==0\n")
    (tmp_path / "runtime" / "python" / "Lib").mkdir(parents=True)
    (tmp_path / "runtime" / "python" / "python312.dll").write_bytes(b"dll")
    (tmp_path / "runtime" / "python" / "Lib" / "os.py").write_text("# os\n")
    (tmp_path / "runtime" / "NodeWatchBackend.exe").write_bytes(b"host")
    monkeypatch.setattr(gi, "ROOT", tmp_path)
    files = gi.collect()
    assert {
        "runtime/python/python312.dll",
        "runtime/python/Lib/os.py",
        "runtime/NodeWatchBackend.exe",
        "app/main.py",
        "requirements.txt",
    } <= set(files)
    assert files["runtime/python/python312.dll"] == gi.sha256(tmp_path / "runtime/python/python312.dll")


# --- release/native_launcher.go and release/backend_host -----------------------


def test_launcher_prefers_bundled_interpreter_and_keeps_fallbacks():
    src = (ROOT / "release/native_launcher.go").read_text(encoding="utf-8")
    find = src.split("func findPython(bundled string)", 1)[1].split("\nfunc ", 1)[0]
    # Bundled interpreter first, then py.exe / per-user installs / PATH as before.
    assert find.index("bundled") < find.index('exec.LookPath("py.exe")') < find.index('"python.exe", "python3.exe"')
    assert 'bundledPythonDir = "runtime/python"' in src
    # The legacy embeddable NodeWatchBackend.exe runtime still works when runtime\python is absent.
    assert 'fileExists(bundled) && l.bundledPython() == ""' in src
    # venv + pip install flow is unchanged.
    assert '"-m", "venv", runtimeDir' in src and '"-m", "pip", "install"' in src


def test_launcher_host_falls_back_to_venv_python():
    src = (ROOT / "release/native_launcher.go").read_text(encoding="utf-8")
    attempts = src.split("func (l *launcher) backendAttempts(py string)", 1)[1].split("\nfunc ", 1)[0]
    assert "return []backendAttempt{host, fallback}" in attempts
    assert "return []backendAttempt{fallback}" in attempts
    host = src.split("func (l *launcher) backendHostAttempt(py string)", 1)[1].split("\nfunc ", 1)[0]
    assert '"PYTHONHOME=" + home' in host and '"PYTHONPATH=" + site' in host
    assert "readVenvHome" in host and "samePath(venvHome, home)" in host
    wait = src.split("func (l *launcher) waitForBackend(", 1)[1].split("\nfunc ", 1)[0]
    assert "case <-exited:" in wait
    main = src.split("func main() {", 1)[1].split("\nfunc ", 1)[0]
    assert "for i, a := range attempts" in main and "_ = cmd.Process.Kill()" in main
    assert "CreationFlags: createNoWindow" in src.split("func (l *launcher) startBackend(", 1)[1].split("\nfunc ", 1)[0]
    # Stale-backend retirement recognises the host executable name.
    assert 'base == "nodewatchbackend.exe"' in src


def test_backend_host_source():
    src = (ROOT / "release/backend_host/main.go").read_text(encoding="utf-8")
    assert "//go:build windows" in src
    assert 'pythonDLLName = "python312.dll"' in src and 'FindProc("Py_Main")' in src
    assert "PYTHONHOME" in src and "SetDllDirectoryW" in src
    assert "import \"C\"" not in src  # pure Go, CGO_ENABLED=0
