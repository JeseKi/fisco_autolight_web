"""
节点进程管理服务 (v2)。

负责启动、停止和监控通过 build_chain.sh 创建的 FISCO 节点进程。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path

from loguru import logger
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ..schemas import NodeStatus
from .node_setup import _get_build_chain_layout_paths, _is_build_chain_layout_ready


def _is_process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _log_group_observability() -> None:
    """打印群组相关的关键信息：group_id、genesis 是否存在、账本目录是否存在、本节点 nodeID。"""
    if not _is_build_chain_layout_ready():
        return
        
    p = _get_build_chain_layout_paths()
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


def _log_tls_info() -> None:
    """打印 TLS 证书与 CA 证书信息。"""
    if not _is_build_chain_layout_ready():
        return
        
    p = _get_build_chain_layout_paths()
    try:
        ssl_crt_path = p["ssl_crt"]
        ca_crt_path = p["ca_crt"]
        if ssl_crt_path.exists():
            cert = x509.load_pem_x509_certificate(ssl_crt_path.read_bytes())
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial = format(cert.serial_number, 'x')
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            fp = cert.fingerprint(hashes.SHA256()).hex()
            logger.info(
                f"TLS 证书信息: subject={subject}, issuer={issuer}, serial=0x{serial}, "
                f"not_before={not_before}, not_after={not_after}, sha256={fp}"
            )
        if ca_crt_path.exists():
            ca = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())
            subject = ca.subject.rfc4514_string()
            serial = format(ca.serial_number, 'x')
            fp = ca.fingerprint(hashes.SHA256()).hex()
            logger.info(
                f"CA 证书信息: subject={subject}, serial=0x{serial}, sha256={fp}"
            )
    except Exception as e:
        logger.debug(f"打印 TLS 证书信息失败：{e}")


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


def _parse_ports_from_config(config_path: Path) -> tuple[int, int]:
    """从 config.ini 解析 p2p.listen_port 与 rpc.listen_port。"""
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


def start_node() -> NodeStatus:
    """启动 FISCO 节点进程。"""
    if not _is_build_chain_layout_ready():
        raise RuntimeError("节点布局未就绪，请先运行 build_chain.sh 创建节点")
    
    p = _get_build_chain_layout_paths()
    
    # 若已有 PID 且存活，直接返回
    if p["pid"].exists():
        try:
            pid = int(p["pid"].read_text().strip())
        except Exception:
            pid = None
        if pid and _is_process_running(pid):
            logger.info("检测到已有 fisco-bcos 进程在运行，跳过启动")
            return get_node_status()

    # 启动新进程：必须使用 start.sh 脚本
    start_sh = p["base"] / "start.sh"
    if start_sh.exists():
        logger.info("检测到 start.sh，使用脚本方式启动 FISCO 节点")
        proc = subprocess.Popen(["bash", str(start_sh)], cwd=str(p["base"]))
        time.sleep(0.3)
        pid = proc.pid
        p["pid"].write_text(str(pid))
    else:
        raise RuntimeError("找不到 start.sh 脚本，无法启动节点")

    # 从配置中获取 RPC 端口用于探测
    rpc_port = 20200
    try:
        p2p_port, rpc_port = _parse_ports_from_config(p["config_ini"])
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
    # 打印 TLS 覆盖证明
    try:
        _log_tls_info()
    except Exception:
        pass
    return s


def stop_node() -> None:
    """停止 FISCO 节点：优先使用 stop.sh，否则杀死 PID。"""
    if not _is_build_chain_layout_ready():
        return
        
    p = _get_build_chain_layout_paths()
    stop_sh = p["base"] / "stop.sh"
    if stop_sh.exists():
        subprocess.run(["bash", str(stop_sh)], cwd=str(p["base"]), check=False)
        return
    if p["pid"].exists():
        try:
            pid = int(p["pid"].read_text().strip())
            os.kill(pid, 15)
        except Exception:
            pass


def get_node_status() -> NodeStatus:
    if not _is_build_chain_layout_ready():
        # 返回未初始化状态
        return NodeStatus(
            initialized=False,
            running=False,
            pid=None,
            base_dir=str(_get_build_chain_layout_paths()["base"]),
            p2p_port=30300,
            rpc_port=20200,
        )
    
    p = _get_build_chain_layout_paths()
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