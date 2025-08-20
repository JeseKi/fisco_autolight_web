"""
节点进程管理服务。

负责启动、停止和监控 FISCO 节点进程的生命周期。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path

from loguru import logger

from ..schemas import NodeStatus
from .node_setup import _paths, _ensure_binary


def _is_process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _log_group_observability() -> None:
    """打印群组相关的关键信息：group_id、genesis 是否存在、账本目录是否存在、本节点 nodeID。"""
    p = _paths()
    gid = os.environ.get("FISCO_GROUP_ID", "group0")
    genesis_path = p["conf"] / f"group.{gid}.genesis"
    data_group_dir = p["data"] / "group" / gid
    nodeid_path = p["conf"] / "node.nodeid"

    info = {
        "group_id": gid,
        "genesis_exists": genesis_path.exists(),
        "data_group_dir_exists": data_group_dir.exists(),
    }
    if nodeid_path.exists():
        try:
            info["node_id"] = nodeid_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass

    logger.info(f"群组可观测信息: {json.dumps(info, ensure_ascii=False)}")


def _probe_rpc_ready(port: int, timeout_s: int = 15) -> bool:
    """通过 TCP 连接探测 RPC 端口是否就绪。"""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    return True
            except Exception:
                pass
        time.sleep(0.3)
    return False


def _start_process(config_path: Path) -> int:
    p = _paths()
    binary = p["binary"]
    if not binary.exists():
        # 若缺失则尝试下载
        _ensure_binary()
    if not binary.exists():
        raise RuntimeError("找不到 fisco-bcos 可执行文件")
    # 以基目录为工作目录启动
    proc = subprocess.Popen(
        [str(binary), "-c", str(config_path)],
        cwd=str(p["base"]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # 启动后短暂等待，若子进程立即退出则不返回 PID
    time.sleep(0.2)
    ret = proc.poll()
    if ret is not None:
        raise RuntimeError(f"fisco-bcos 启动失败，退出码 {ret}")
    return proc.pid


def start_node() -> NodeStatus:
    """启动 FISCO 节点进程。"""
    p = _paths()
    
    # 若已有 PID 且存活，直接返回
    if p["pid"].exists():
        try:
            pid = int(p["pid"].read_text().strip())
        except Exception:
            pid = None
        if pid and _is_process_running(pid):
            logger.info("检测到已有 fisco-bcos 进程在运行，跳过启动")
            return get_node_status()

    # 启动新进程
    pid = _start_process(p["config_ini"])
    p["pid"].write_text(str(pid))

    # 从配置中获取 RPC 端口用于探测
    rpc_port = 20200
    try:
        # 简单解析 config.ini 获取 rpc_port
        for line in p["config_ini"].read_text(encoding="utf-8").splitlines():
            if "listen_port=" in line and "[rpc]" in line:
                rpc_port = int(line.split("=", 1)[1].strip())
                break
    except Exception:
        pass

    # 等待 RPC 就绪
    if not _probe_rpc_ready(rpc_port, timeout_s=20):
        # 若端口未就绪，进一步检测子进程是否已退出
        try:
            saved_pid = int(p["pid"].read_text().strip())
            if not _is_process_running(saved_pid):
                raise RuntimeError("fisco-bcos 进程已退出（可能为僵尸/快速退出）")
        except Exception:
            pass
        logger.warning("RPC 端口在预期时间内未就绪，进程可能仍在初始化")

    # 记录状态文件
    s = get_node_status()
    p["status"].write_text(json.dumps(s.model_dump(), ensure_ascii=False, indent=2), encoding="utf-8")
    # 打印群组可观测信息（基于磁盘与配置，不依赖 RPC）
    try:
        _log_group_observability()
    except Exception as e:
        logger.debug(f"记录群组可观测信息失败：{e}")
    return s


def get_node_status() -> NodeStatus:
    p = _paths()
    p2p_port = 30300
    rpc_port = 20200

    # 解析实际端口
    try:
        p2p_port, rpc_port = _parse_ports_from_config(p["config_ini"])
    except Exception:
        pass

    initialized = all(
        [
            p["config_ini"].exists(),
            p["ssl_key"].exists(),
            p["ssl_crt"].exists(),
            p["ca_crt"].exists(),
        ]
    )
    pid = None
    running = False
    if p["pid"].exists():
        try:
            pid = int(p["pid"].read_text().strip())
            running = _is_process_running(pid)
        except Exception:
            pid = None
            running = False

    return NodeStatus(
        initialized=initialized,
        running=running,
        pid=pid,
        base_dir=str(p["base"]),
        p2p_port=p2p_port,
        rpc_port=rpc_port,
    )


def _parse_ports_from_config(config_path: Path) -> tuple[int, int]:
    """从已有 config.ini 解析 p2p.listen_port 与 rpc.listen_port。"""
    p2p_port = 30300
    rpc_port = 20200
    section = None
    try:
        for raw in config_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line.strip("[]").lower()
                continue
            if "listen_port=" in line:
                try:
                    value = int(line.split("=", 1)[1].strip())
                except Exception:
                    continue
                if section == "p2p":
                    p2p_port = value
                elif section == "rpc":
                    rpc_port = value
    except Exception:
        pass
    return p2p_port, rpc_port