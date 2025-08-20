"""
证书签发服务的核心逻辑实现。
包括生成挑战、验证签名、调用 step CLI 签发证书等。
"""

import base64
import hashlib
import hmac
import os
import secrets
import subprocess
import tempfile
from typing import Dict
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from datetime import datetime, timedelta, timezone
from loguru import logger
from src.server.config import config

# 模拟缓存挑战（生产环境建议用 Redis 或数据库）
CHALLENGE_STORE: Dict[str, Dict[str, str]] = {}


def generate_challenge() -> str:
    """
    生成一个安全的随机挑战字符串。
    :return: Base64 URL 安全编码的随机字符串。
    """
    return secrets.token_urlsafe(32)


def store_challenge(challenge: str, data: Dict[str, str]) -> None:
    """
    将挑战及其关联数据存储起来。
    :param challenge: 挑战字符串。
    :param data: 关联数据，如 original_node_id 和 public_key。
    """
    CHALLENGE_STORE[challenge] = data


def get_challenge_data(challenge: str) -> Dict[str, str] | None:
    """
    根据挑战字符串获取其关联数据。
    :param challenge: 挑战字符串。
    :return: 关联数据字典，如果不存在则返回 None。
    """
    return CHALLENGE_STORE.get(challenge)


def remove_challenge(challenge: str) -> None:
    """
    从存储中移除已使用的挑战。
    :param challenge: 挑战字符串。
    """
    CHALLENGE_STORE.pop(challenge, None)


def verify_signature(public_key_b64: str, message: str, signature_b64: str) -> bool:
    """
    使用客户端提供的公钥验证签名。
    :param public_key_b64: Base64 编码的 PEM 格式公钥。
    :param message: 待验证的消息。
    :param signature_b64: Base64 编码的签名。
    :return: 验证成功返回 True，否则返回 False。
    """
    try:
        public_key_bytes = base64.b64decode(public_key_b64)
        loaded_public_key = serialization.load_pem_public_key(public_key_bytes)
        signature = base64.b64decode(signature_b64)

        if not isinstance(loaded_public_key, ec.EllipticCurvePublicKey):
            return False

        loaded_public_key.verify(
            signature,
            message.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (ValueError, InvalidSignature):
        return False


def generate_secure_node_name(original_node_id: str, public_key_b64: str) -> str:
    """
    使用公钥和原始节点 ID 生成唯一的、安全的 node_name。
    :param original_node_id: 客户端原始节点 ID。
    :param public_key_b64: Base64 编码的 PEM 格式公钥。
    :return: 生成的 node_name (SHA256 HMAC hex digest)。
    """
    key = base64.b64decode(public_key_b64)
    return hmac.new(key, original_node_id.encode(), hashlib.sha256).hexdigest()


def extract_public_key_from_csr(csr_b64: str) -> str:
    """
    从 Base64 编码的 CSR 中提取公钥，并返回 Base64 编码的 PEM 格式公钥。
    :param csr_b64: Base64 编码的 PEM 格式 CSR。
    :return: Base64 编码的 PEM 格式公钥。
    :raises ValueError: 如果 CSR 无效。
    """
    try:
        csr_bytes = base64.b64decode(csr_b64)
        csr = x509.load_pem_x509_csr(csr_bytes)
        public_key = csr.public_key()
        
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_key_pem).decode('utf-8')
    except Exception as e:
        logger.error(f"从 CSR 提取公钥失败: {e}")
        raise ValueError("无效的 CSR 格式")


def issue_certificate_with_step_cli(
    secure_node_name: str, csr_b64: str
) -> Dict[str, str]:
    """
    调用 step CLI 对客户端提供的 CSR 进行签名。
    :param secure_node_name: 为证书生成的唯一名称 (将作为 Common Name)。
    :param csr_b64: Base64 编码的 PEM 格式的 CSR。
    :return: 包含证书和 CA 证书链的字典。
    :raises RuntimeError: 如果签发过程失败。
    """
    steppath = os.environ.get("STEPPATH", os.path.expanduser("~/.step"))
    # 优先使用环境变量指定的远程 CA 根证书，其次回退到本地 Step 路径
    env_root = os.environ.get("STEP_CA_ROOT")
    ca_root_path = env_root if env_root else os.path.join(steppath, "certs", "root_ca.crt")
    
    if not os.path.exists(ca_root_path):
        raise RuntimeError(f"CA 根证书未找到: {ca_root_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        csr_path = os.path.join(tmpdir, "node.csr")
        crt_path = os.path.join(tmpdir, "node.crt")

        with open(csr_path, "wb") as f:
            f.write(base64.b64decode(csr_b64))

        # 构建 step ca sign 命令，确保参数顺序正确
        # 注意：step ca sign 的基本用法是 `step ca sign <csr-file> <crt-file>`
        # 但可能需要指定 --not-after, --not-before 等选项，这里为了简化没有添加
        # 如果需要为证书设置特定的 Common Name，通常是在 CSR 中完成的
        cmd = [
            "step",
            "ca",
            "sign",
            csr_path,  # <csr-file>
            crt_path,  # <crt-file>
            "-f",
        ]
        # 选择在线或离线模式，并在在线模式下显式指定 CA URL 与根证书
        step_ca_url = os.environ.get("STEP_CA_URL")
        # 默认启用离线模式，可通过 STEP_CA_OFFLINE=0/false 显式关闭
        step_ca_offline = os.environ.get("STEP_CA_OFFLINE", "1").lower() in {"1", "true", "yes"}
        step_ca_token = os.environ.get("STEP_CA_TOKEN")
        step_ca_prov = os.environ.get("STEP_CA_PROVISIONER")

        if step_ca_offline:
            cmd.append("--offline")
            logger.debug("使用离线模式签发证书 (--offline)")
        else:
            if step_ca_url:
                cmd.extend(["--ca-url", step_ca_url])
            cmd.extend(["--root", ca_root_path])
            if step_ca_prov:
                cmd.extend(["--issuer", step_ca_prov])
            if step_ca_token:
                cmd.extend(["--token", step_ca_token])
            logger.debug(f"使用在线模式签发证书 (--ca-url={step_ca_url or '[context default]'}, --root={ca_root_path})")
        
        # 打印调试信息
        logger.debug(f"Executing command: {' '.join(cmd)}")
        
        # 执行命令
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            error_msg = f"证书签发失败 (signing CSR): {result.stderr}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        with open(ca_root_path, "rb") as f:
            ca_data = base64.b64encode(f.read()).decode("utf-8")

        with open(crt_path, "rb") as f:
            cert_data = base64.b64encode(f.read()).decode("utf-8")

        return {"certificate": cert_data, "ca_bundle": ca_data}


def _get_dev_ca_dir() -> str:
    """
    获取开发用 CA 的存储目录。
    优先使用环境变量 DEV_CA_DIR，其次使用与当前模块同级的 dev_ca 目录。
    """
    return os.environ.get(
        "DEV_CA_DIR", os.path.join(os.path.dirname(__file__), "dev_ca")
    )


def _get_dev_ca_paths() -> Dict[str, str]:
    """返回 CA 私钥、证书与序列号文件的路径。"""
    ca_dir = _get_dev_ca_dir()
    return {
        "dir": ca_dir,
        "key": os.path.join(ca_dir, "ca_key.pem"),
        "cert": os.path.join(ca_dir, "ca_cert.pem"),
        "serial": os.path.join(ca_dir, "serial.txt"),
    }


def _ensure_dir(path: str) -> None:
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def _load_or_create_dev_ca() -> tuple:
    """
    加载或创建开发用自签 CA。
    返回 (ca_private_key, ca_certificate)。
    """
    paths = _get_dev_ca_paths()
    _ensure_dir(paths["dir"])

    key_path = paths["key"]
    cert_path = paths["cert"]

    if os.path.exists(key_path) and os.path.exists(cert_path):
        with open(key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert

    # 生成新的 CA 私钥与自签根证书
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.ca_root_organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, config.ca_root_common_name),
        ]
    )
    now = datetime.now(timezone.utc)
    ca_cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    ca_cert = ca_cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    with open(key_path, "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(Encoding.PEM))

    # 初始化序列号文件
    with open(paths["serial"], "w", encoding="utf-8") as f:
        f.write("1\n")

    return ca_key, ca_cert


def _next_serial() -> int:
    """简单的序列号分配（仅用于教学环境）。"""
    paths = _get_dev_ca_paths()
    serial_path = paths["serial"]
    _ensure_dir(paths["dir"])
    current = 1
    if os.path.exists(serial_path):
        with open(serial_path, "r", encoding="utf-8") as f:
            try:
                current = int(f.read().strip() or "1")
            except Exception:
                current = 1
    with open(serial_path, "w", encoding="utf-8") as f:
        f.write(str(current + 1) + "\n")
    return current


def issue_certificate_with_local_ca(csr_b64: str) -> Dict[str, str]:
    """
    使用本地开发 CA 对 CSR 进行签名并返回证书与 CA 证书链。
    :param csr_b64: Base64 编码的 PEM CSR。
    :return: {"certificate": base64(pem), "ca_bundle": base64(pem)}
    :raises ValueError / RuntimeError
    """
    try:
        ca_key, ca_cert = _load_or_create_dev_ca()
    except Exception as e:
        logger.error(f"加载/创建开发 CA 失败: {e}")
        raise RuntimeError("开发 CA 初始化失败")

    try:
        csr_bytes = base64.b64decode(csr_b64)
        csr = x509.load_pem_x509_csr(csr_bytes)
    except Exception:
        raise ValueError("无效的 CSR 格式")

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(_next_serial())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )

    # 复制 CSR 中请求的扩展（如 SAN）
    try:
        for ext in csr.extensions:
            # 避免重复添加 BasicConstraints / KeyUsage / ExtendedKeyUsage
            if isinstance(ext.value, x509.BasicConstraints):
                continue
            if isinstance(ext.value, x509.KeyUsage):
                continue
            if isinstance(ext.value, x509.ExtendedKeyUsage):
                continue
            builder = builder.add_extension(ext.value, critical=ext.critical)
    except Exception:
        pass

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    cert_b64 = base64.b64encode(cert.public_bytes(Encoding.PEM)).decode("utf-8")
    ca_b64 = base64.b64encode(ca_cert.public_bytes(Encoding.PEM)).decode("utf-8")

    return {"certificate": cert_b64, "ca_bundle": ca_b64}


def _load_certificate_from_input(certificate_input: str) -> x509.Certificate:
    """
    尝试从输入中解析证书，兼容以下多种输入形式：
    1) 直接的 PEM 文本（包含 -----BEGIN CERTIFICATE-----）
    2) 仅包含证书 PEM 的一段文本（从中提取首个证书块）
    3) Base64 编码的 PEM 文本
    4) DER 二进制（以 Base64 字符串形式传入）

    :param certificate_input: 证书输入字符串
    :return: 解析得到的 x509.Certificate 对象
    :raises ValueError: 当无法识别/解析证书时
    """
    text = certificate_input.strip()

    # 情况 1/2：文本中已经包含 PEM 头
    if "-----BEGIN CERTIFICATE-----" in text:
        try:
            # 直接按完整 PEM 尝试
            return x509.load_pem_x509_certificate(text.encode("utf-8"))
        except Exception:
            # 尝试提取第一段 PEM 块
            try:
                pem_blocks = re.findall(
                    r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----",
                    text,
                )
                if pem_blocks:
                    return x509.load_pem_x509_certificate(pem_blocks[0].encode("utf-8"))
            except Exception:
                pass

    # 情况 3/4：尝试作为 Base64 字符串解码后再解析（先 PEM，失败再 DER）
    try:
        decoded = base64.b64decode(text)
        # 优先尝试 PEM
        try:
            return x509.load_pem_x509_certificate(decoded)
        except Exception:
            # 再尝试 DER
            return x509.load_der_x509_certificate(decoded)
    except Exception:
        pass

    raise ValueError("无法从输入中解析证书")


def verify_certificate_issued_by_us(cert_input: str) -> dict:
    """
    验证一个证书是否由我们自己签发。
    通过比较证书的签发者与我们 CA 证书的主体来判断。
    
    :param cert_input: 证书内容（支持 PEM 文本 或 Base64 编码的 PEM/DER）。
    :return: 包含验证结果、签发者和主题 CN 的字典。
             例如: {"is_issued_by_us": True, "issuer_cn": "...", "subject_cn": "..."}
    """
    try:
        # 1. 加载待验证的证书（兼容 PEM / Base64 PEM / Base64 DER）
        cert = _load_certificate_from_input(cert_input)
        
        # 2. 获取我们自己的 CA 证书
        _, ca_cert = _load_or_create_dev_ca()
        
        # 3. 比较签发者 (Issuer) 和我们 CA 的主体 (Subject)
        is_issued_by_us = cert.issuer == ca_cert.subject
        
        # 4. 提取 Issuer 和 Subject 的 Common Name (CN)
        def _get_cn_from_name(name: x509.Name) -> str | None:
            try:
                return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except (IndexError, AttributeError):
                return None
                
        issuer_cn = _get_cn_from_name(cert.issuer)
        subject_cn = _get_cn_from_name(cert.subject)
        
        return {
            "is_issued_by_us": is_issued_by_us,
            "issuer_common_name": issuer_cn,
            "subject_common_name": subject_cn,
        }
        
    except Exception as e:
        # 无效的用户输入通常不应视为服务器错误，降级为 warning 以减少干扰
        logger.warning(f"验证证书归属时发生错误: {e}")
        # 如果解析失败，也认为不是我们签发的
        return {
            "is_issued_by_us": False,
            "issuer_common_name": None,
            "subject_common_name": None,
        }