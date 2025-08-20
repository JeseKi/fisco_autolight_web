"""
节点初始化与配置服务。

负责节点运行环境的初始化，包括目录创建、配置文件生成、证书与密钥生成等。
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Dict

from loguru import logger
import httpx

from src.server.config import config
# 复用 CA 内部实现
from src.server.ca.core import _load_or_create_dev_ca, issue_certificate_with_local_ca


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
    return (Path(__file__).resolve().parent.parent / "runtime").absolute()


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
        "binary": Path(__file__).resolve().parent.parent / "fisco-bcos",
        "template_config": Path(__file__).resolve().parent.parent / "config.ini",
        "template_genesis": Path(__file__).resolve().parent.parent / "config.genesis",
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


def _ensure_consensus_key_and_genesis(group_id: str | None = None) -> None:
    """确保共识私钥与创世文件存在：
    - 若缺少 conf/node.pem 则生成 secp256k1 私钥
    - 读取模板 src/server/fisco/config.genesis，替换 group_id 与 node 列表，仅保留 node.0=<nodeid>: 1
    - 将结果写入 runtime/conf/group.<group_id>.genesis
    """
    p = _paths()
    conf_dir = p["conf"]
    conf_dir.mkdir(parents=True, exist_ok=True)

    # 1) 生成/加载 secp256k1 共识私钥
    node_key_path = conf_dir / "node.pem"
    if not node_key_path.exists():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256K1())
        node_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 2) 由 node.pem 推导 nodeID（未压缩公钥去掉 0x04 前缀，x||y 组成的 64 字节 -> 128 hex）
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    loaded_key = serialization.load_pem_private_key(node_key_path.read_bytes(), password=None)
    if not isinstance(loaded_key, ec.EllipticCurvePrivateKey) or not isinstance(loaded_key.curve, ec.SECP256K1):
        raise RuntimeError("conf/node.pem 不是 secp256k1 私钥")
    pub = loaded_key.public_key().public_numbers()
    x_hex = format(pub.x, '064x')
    y_hex = format(pub.y, '064x')
    node_id_hex = f"{x_hex}{y_hex}"

    # 便于排查：写出 node.nodeid 文件
    nodeid_path = conf_dir / "node.nodeid"
    nodeid_path.write_text(node_id_hex + "\n", encoding="utf-8")

    # 3) 基于模板生成 group.<group_id>.genesis
    gid = group_id or os.environ.get("FISCO_GROUP_ID", "group0")
    template_path = p["template_genesis"]
    if not template_path.exists():
        logger.warning("未找到 config.genesis 模板，跳过创世写入")
        return
    text = template_path.read_text(encoding="utf-8").splitlines()

    out_lines: list[str] = []
    in_consensus = False
    for line in text:
        raw = line.rstrip("\n")
        stripped = raw.strip()
        # 替换 group_id
        if stripped.startswith("group_id="):
            out_lines.append(raw[:raw.index("g")] + f"group_id={gid}") if "g" in raw else out_lines.append(f"group_id={gid}")
            continue
        # 共识段开始/结束识别
        if stripped.startswith("[consensus]"):
            in_consensus = True
            out_lines.append(raw)
            continue
        if in_consensus and stripped.startswith("[") and stripped.endswith("]"):
            # 离开共识段时，写入我们唯一的 node.0 行
            out_lines.append(f"    node.0={node_id_hex}: 1")
            in_consensus = False
            out_lines.append(raw)
            continue
        if in_consensus:
            # 过滤掉 node.N=... 行，其余配置原样保留
            if stripped.startswith("node."):
                continue
            out_lines.append(raw)
            continue
        out_lines.append(raw)

    # 若模板中 [consensus] 是最后一段，需要在文件末尾写入 node.0 行
    if in_consensus:
        out_lines.append(f"    node.0={node_id_hex}: 1")

    # 写入 conf/group.<gid>.genesis（便于多群组管理）
    conf_genesis = conf_dir / f"group.{gid}.genesis"
    conf_genesis.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    # 同步写入运行根目录 config.genesis（与官方 build_chain 布局兼容，提升启动成功率）
    base_genesis = p["base"] / "config.genesis"
    base_genesis.write_text("\n".join(out_lines) + "\n", encoding="utf-8")


def _is_build_chain_layout(base: Path) -> bool:
    """是否为 build_chain 产出的节点布局：根目录下有 config.genesis 与 config.ini。"""
    return (base / "config.genesis").exists() and (base / "config.ini").exists()


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