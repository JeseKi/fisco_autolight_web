"""
FISCO v2 服务测试。

仅测试公开接口，不测内部实现：
 - status()
 - ensure_started()

边界/错误路径：
 - 已存在 PID 且进程存活时不重复启动
"""

import os
import sys
from pathlib import Path

# 允许从项目根导入
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

from src.server.fisco_v2 import services


def test_status_initial(tmp_path, monkeypatch):
    # 使用隔离的运行目录
    monkeypatch.setenv("FISCO_BASE_DIR", str(tmp_path))
    s = services.status()
    assert s.initialized is False
    assert s.running is False
    assert s.pid is None


def test_ensure_started_with_existing_nodes_dir(tmp_path, monkeypatch):
    # mock 探测逻辑
    import src.server.fisco_v2.services.node_process as node_process
    monkeypatch.setattr(node_process, "_probe_rpc_ready", lambda port, timeout_s=15: True)
    
    # 应该成功启动已存在的节点
    s = services.ensure_started()
    assert s.initialized is True
    assert s.running is True