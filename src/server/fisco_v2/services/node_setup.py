"""
节点初始化与配置服务 (v2)。

负责通过 build_chain.sh 脚本创建和管理 FISCO 节点。
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
import base64

from loguru import logger
from src.server.ca.core import _load_or_create_dev_ca, issue_certificate_with_local_ca


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def _get_code_dir() -> Path:
    """获取代码目录。"""
    return Path(__file__).resolve().parent.parent


def _get_build_chain_sh_path() -> Path:
    """获取 build_chain.sh 脚本路径。"""
    code_dir = _get_code_dir()
    return code_dir / "build_chain.sh"


def _ensure_build_chain_sh() -> None:
    """确保 build_chain.sh 脚本存在。"""
    sh_path = _get_build_chain_sh_path()
    if not sh_path.exists():
        raise RuntimeError(f"找不到 build_chain.sh 脚本: {sh_path}")


def _get_default_node_path() -> Path:
    """获取默认节点路径。"""
    code_dir = _get_code_dir()
    return code_dir / "nodes" / "127.0.0.1" / "node0"


def _is_build_chain_layout_ready() -> bool:
    """检查是否已经通过 build_chain.sh 创建了节点布局。"""
    node_path = _get_default_node_path()
    config_ini = node_path / "config.ini"
    config_genesis = node_path / "config.genesis"
    start_sh = node_path / "start.sh"
    
    return node_path.exists() and config_ini.exists() and config_genesis.exists() and start_sh.exists()


def _get_build_chain_layout_paths() -> dict[str, Path]:
    """获取 build_chain 产出的节点布局路径。"""
    base = _get_default_node_path()
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
    }


def _run_build_chain_sh(p2p_port: int, rpc_port: int) -> None:
    """运行 build_chain.sh 脚本创建节点。"""
    code_dir = _get_code_dir()
    sh_path = _get_build_chain_sh_path()
    
    # 确保脚本有执行权限
    sh_path.chmod(0o755)
    
    # 构建命令
    cmd = ["bash", str(sh_path), "-l", "127.0.0.1:1", "-p", f"{p2p_port},{rpc_port}"]
    
    logger.info(f"执行 build_chain.sh：{' '.join(cmd)}")
    
    try:
        # 运行 build_chain.sh
        result = subprocess.run(
            cmd,
            cwd=str(code_dir),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        logger.info(f"build_chain.sh 执行成功: {result.stdout}")
        
        # 检查节点目录是否创建成功
        if not _is_build_chain_layout_ready():
            raise RuntimeError("build_chain.sh 执行完成，但节点目录未正确创建")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"build_chain.sh 执行失败: {e.stderr}")
        raise RuntimeError(f"build_chain.sh 执行失败: {e.stderr}")
    except Exception as e:
        logger.error(f"运行 build_chain.sh 时发生未知错误: {str(e)}")
        raise RuntimeError(f"运行 build_chain.sh 时发生未知错误: {str(e)}")


def overwrite_tls_with_internal_ca() -> None:
    """使用内部 CA 覆盖节点的 TLS（ssl.key、ssl.crt、ca.crt）。

    - 始终覆盖，确保服务端统一 CA。
    - 生成新 ECDSA 私钥，基于其 CSR 由内部 CA 签发证书。
    """
    if not _is_build_chain_layout_ready():
        return
    p = _get_build_chain_layout_paths()
    conf_dir = p["conf"]
    conf_dir.mkdir(parents=True, exist_ok=True)

    # 确保内部 CA 就绪
    _load_or_create_dev_ca()

    # 生成新的 ECDSA P-256 私钥与 CSR
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    from src.server.config import config as app_config
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, app_config.node_cert_organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, app_config.node_cert_common_name),
    ])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_b64 = base64.b64encode(csr_pem).decode("utf-8")

    result = issue_certificate_with_local_ca(csr_b64)

    # 覆盖写入 TLS 三件
    (conf_dir / "ssl.key").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (conf_dir / "ssl.crt").write_bytes(base64.b64decode(result["certificate"]))
    (conf_dir / "ca.crt").write_bytes(base64.b64decode(result["ca_bundle"]))

    logger.info("已使用内部 CA 覆盖 TLS 证书与私钥：conf/ssl.key、conf/ssl.crt、conf/ca.crt")