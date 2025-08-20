"""
文件功能：
    节点管理服务：负责在服务器启动时保证本地共识节点被初始化并启动。

公开接口：
    - ensure_started() -> NodeStatus: 确保节点已启动，若未初始化/未运行则执行初始化与启动
    - status() -> NodeStatus: 获取节点状态

内部方法：
    - _get_base_dir() -> str: 运行基目录
    - _paths() -> dict: 运行目录相关路径
    - _ensure_dirs(): 创建必要目录
    - _write_config_if_absent(p2p_port: int, rpc_port: int): 写入固定 config.ini
    - _write_nodes_if_absent(): 写入最小 nodes.json
    - _generate_key_and_cert(): 生成私钥/CSR并使用本地开发 CA 签名
    - _start_process(): 启动 fisco-bcos 进程
    - _is_process_running(pid: int) -> bool: 判断 PID 是否仍在运行
    - _probe_rpc_ready(timeout_s: int) -> bool: 探测 RPC 端口

说明：
    - 代码中的注释与日志均为中文。
    - P2P/RPC 端口支持通过环境变量 FISCO_P2P_PORT 与 FISCO_RPC_PORT 覆盖。
    - 默认基目录为 src/server/fisco 目录下的 runtime 子目录，可用 FISCO_BASE_DIR 覆盖。
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict

from loguru import logger
import httpx

from .schemas import NodeStatus

# 复用 CA 内部实现
from src.server.ca.core import _load_or_create_dev_ca, issue_certificate_with_local_ca
from src.server.config import config


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def _get_base_dir() -> Path:
    """获取运行基目录，默认位于源码树内的 src/server/fisco/runtime。"""
    env = os.environ.get("FISCO_BASE_DIR")
    if env:
        return Path(env).absolute()
    # 默认与仓库中的二进制和模板同级，避免污染源码：使用 runtime 子目录
    return (Path(__file__).resolve().parent / "runtime").absolute()


def _paths() -> Dict[str, Path]:
    base = _get_base_dir()
    return {
        "base": base,
        "conf": base / "conf",
        "data": base / "data",
        "log": base / "log",
        "config_ini": base / "config.ini",
        "nodes_json": base / "nodes.json",
        "ssl_key": base / "conf" / "ssl.key",
        "ssl_crt": base / "conf" / "ssl.crt",
        "ca_crt": base / "conf" / "ca.crt",
        "pid": base / "node.pid",
        "status": base / "node_status.json",
        "binary": Path(__file__).resolve().parent / "fisco-bcos",
        "template_config": Path(__file__).resolve().parent / "config.ini",
    }


def _ensure_dirs() -> None:
    p = _paths()
    for key in ("base", "conf", "data", "log"):
        p[key].mkdir(parents=True, exist_ok=True)


def _write_config_if_absent(p2p_port: int, rpc_port: int) -> None:
    p = _paths()
    if p["config_ini"].exists():
        return
    # 读取模板并保持大部分固定，仅替换端口与路径相关项
    content = p["template_config"].read_text(encoding="utf-8")
    # 简单替换：listen_port、ca_path、data_path、nodes_path
    content = content.replace("listen_port=30300", f"listen_port={p2p_port}")
    content = content.replace("listen_port=20200", f"listen_port={rpc_port}")
    content = content.replace("ca_path=./conf", "ca_path=./conf")
    content = content.replace("data_path=data", "data_path=data")
    content = content.replace("nodes_path=./", "nodes_path=./")
    p["config_ini"].write_text(content, encoding="utf-8")


def _write_nodes_if_absent() -> None:
    p = _paths()
    if p["nodes_json"].exists():
        return
    # 单节点初始，生成空数组，未来可补充自身 node 信息
    p["nodes_json"].write_text("[]\n", encoding="utf-8")


def _generate_key_and_cert() -> None:
    p = _paths()
    # 若证书文件已存在则跳过
    if p["ssl_key"].exists() and p["ssl_crt"].exists() and p["ca_crt"].exists():
        return
    # 确保 CA 已就绪
    _load_or_create_dev_ca()
    # 生成临时 ECDSA 私钥与 CSR
    # 为复用 ca.core 中的逻辑，我们只需要构造一个 CSR 并调用 issue_certificate_with_local_ca
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fisco Local Node"),
            x509.NameAttribute(NameOID.COMMON_NAME, "local-node"),
        ]
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_b64 = base64.b64encode(s=csr_pem).decode("utf-8")
    result = issue_certificate_with_local_ca(csr_b64)

    # 写入私钥与证书、CA 根证
    p["ssl_key"].write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    p["ssl_crt"].write_bytes(base64.b64decode(result["certificate"]))
    p["ca_crt"].write_bytes(base64.b64decode(result["ca_bundle"]))


def _is_process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


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
    return proc.pid


def _ensure_binary() -> None:
    """确保 fisco-bcos 二进制存在；如不存在则从配置的 URL 下载并赋予可执行权限。"""
    p = _paths()
    binary = p["binary"]
    if binary.exists():
        return
    url = getattr(config, "fisco_url", None)
    if not url:
        logger.error("缺少 fisco_url 配置，无法自动下载 fisco-bcos 二进制")
        return
    binary.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = binary.with_suffix(".downloading")
    logger.info(f"开始下载 fisco-bcos 二进制：{url}")
    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=300) as r:
            r.raise_for_status()
            with open(tmp_path, "wb") as f:
                for chunk in r.iter_bytes():
                    if chunk:
                        f.write(chunk)
        os.chmod(tmp_path, 0o755)
        tmp_path.rename(binary)
        logger.info(f"fisco-bcos 下载完成：{binary}")
    except Exception as e:
        logger.error(f"下载 fisco-bcos 失败：{e}")
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        finally:
            pass


def status() -> NodeStatus:
    p = _paths()
    p2p_port = _get_env_int("FISCO_P2P_PORT", 30300)
    rpc_port = _get_env_int("FISCO_RPC_PORT", 20200)

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


def ensure_started() -> NodeStatus:
    """确保节点已初始化并运行。"""
    _ensure_dirs()
    p2p_port = _get_env_int("FISCO_P2P_PORT", 30300)
    rpc_port = _get_env_int("FISCO_RPC_PORT", 20200)

    _write_config_if_absent(p2p_port=p2p_port, rpc_port=rpc_port)
    _write_nodes_if_absent()
    _generate_key_and_cert()

    p = _paths()

    # 若已有 PID 且存活，直接返回
    if p["pid"].exists():
        try:
            pid = int(p["pid"].read_text().strip())
        except Exception:
            pid = None
        if pid and _is_process_running(pid):
            logger.info("检测到已有 fisco-bcos 进程在运行，跳过启动")
            return status()

    # 启动新进程
    pid = _start_process(p["config_ini"])
    p["pid"].write_text(str(pid))

    # 等待 RPC 就绪
    if not _probe_rpc_ready(rpc_port, timeout_s=20):
        logger.warning("RPC 端口在预期时间内未就绪，进程可能仍在初始化")

    # 记录状态文件
    s = status()
    p["status"].write_text(json.dumps(s.model_dump(), ensure_ascii=False, indent=2), encoding="utf-8")
    return s


