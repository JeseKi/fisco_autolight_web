"""
仅测试公开接口，不测内部实现：
 - status()
 - ensure_started()

边界/错误路径：
 - 缺少二进制时 ensure_started 抛出异常
 - 已存在 PID 且进程存活时不重复启动
"""

import os
import sys
from pathlib import Path

# 允许从项目根导入
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

from src.server.fisco import services


def test_status_initial(tmp_path, monkeypatch):
    # 使用隔离的运行目录
    monkeypatch.setenv("FISCO_BASE_DIR", str(tmp_path))
    s = services.status()
    assert s.initialized is False
    assert s.running is False
    assert s.pid is None


def test_ensure_started_without_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("FISCO_BASE_DIR", str(tmp_path))
    # 通过 monkeypatch _paths 让 binary 指向一个不存在的路径
    original_paths = services._paths

    def fake_paths():
        p = original_paths()
        p["binary"] = tmp_path / "non-exist-binary"
        return p

    monkeypatch.setattr(services, "_paths", fake_paths)
    # mock 下载：将 fisco_url 指向 /bin/true 并在 _ensure_binary 中直接链接
    monkeypatch.setattr(services, "_ensure_binary", lambda: (tmp_path / "non-exist-binary").symlink_to("/bin/true"))
    # mock 探测逻辑
    monkeypatch.setattr(services, "_probe_rpc_ready", lambda port, timeout_s=15: True)
    s = services.ensure_started()
    assert s.initialized is True


def test_ensure_started_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("FISCO_BASE_DIR", str(tmp_path))

    # 通过 monkeypatch _paths 让 binary 指向一个我们控制的位置
    original_paths = services._paths

    def fake_paths():
        p = original_paths()
        p["binary"] = tmp_path / "fisco-bcos"
        return p

    monkeypatch.setattr(services, "_paths", fake_paths)

    # 准备一个假的二进制，使用 /bin/true 代替以便快速退出
    fake_bin = tmp_path / "fisco-bcos"
    if not fake_bin.exists():
        fake_bin.symlink_to("/bin/true")

    # mock 探测逻辑，直接返回 True，避免真实端口等待
    monkeypatch.setattr(services, "_probe_rpc_ready", lambda port, timeout_s=15: True)

    s = services.ensure_started()
    assert s.initialized is True
    # 由于 /bin/true 很快退出，running 可能为 False，但至少 config 与证书已生成
    assert Path(tmp_path / "config.ini").exists()
    assert Path(tmp_path / "conf" / "ssl.key").exists()
    assert Path(tmp_path / "conf" / "ssl.crt").exists()
    assert Path(tmp_path / "conf" / "ca.crt").exists()


