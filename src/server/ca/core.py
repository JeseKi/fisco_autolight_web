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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
    # 注意：在生产环境中，这里应该使用 Redis 或数据库，并设置过期时间
    CHALLENGE_STORE[challenge] = data


def get_challenge_data(challenge: str) -> Dict[str, str] | None:
    """
    根据挑战字符串获取其关联数据。
    :param challenge: 挑战字符串。
    :return: 关联数据字典，如果不存在则返回 None。
    """
    # 注意：在生产环境中，这里应该检查是否过期
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

        # 仅支持 EC 公钥的签名验证，其它类型直接返回失败
        if not isinstance(loaded_public_key, ec.EllipticCurvePublicKey):
            return False

        loaded_public_key.verify(
            signature,
            message.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (ValueError, InvalidSignature):
        # ValueError 可能来自 base64 解码失败或密钥加载失败
        # InvalidSignature 来自签名验证失败
        return False


def generate_secure_node_name(original_node_id: str, public_key_b64: str) -> str:
    """
    使用公钥和原始节点 ID 生成唯一的、安全的 node_name。
    :param original_node_id: 客户端原始节点 ID。
    :param public_key_b64: Base64 编码的 PEM 格式公钥。
    :return: 生成的 node_name (SHA256 HMAC hex digest)。
    """
    # 使用公钥作为密钥，对原始节点 ID 进行 HMAC-SHA256 运算，确保唯一性和抗碰撞性
    key = base64.b64decode(public_key_b64)
    return hmac.new(key, original_node_id.encode(), hashlib.sha256).hexdigest()


def issue_certificate_with_step_cli(
    secure_node_name: str, public_key_b64: str
) -> Dict[str, str]:
    """
    调用 step CLI 基于客户端提供的公钥签发证书。
    :param secure_node_name: 为证书生成的唯一名称。
    :param public_key_b64: Base64 编码的 PEM 格式公钥。
    :return: 包含证书和 CA 证书链的字典。
    :raises RuntimeError: 如果签发过程失败。
    """
    # 获取 CA 证书链路径
    # (此步骤可能需要根据step ca配置调整，或直接读取CA根证书)
    # 假设 STEPPATH 环境变量已设置
    steppath = os.environ.get("STEPPATH", os.path.expanduser("~/.step"))
    ca_root_path = os.path.join(steppath, "certs", "root_ca.crt")
    
    # 先检查 CA 根证书是否存在
    if not os.path.exists(ca_root_path):
        raise RuntimeError(f"CA 根证书未找到: {ca_root_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        pub_key_path = os.path.join(tmpdir, "node.pub")
        crt_path = os.path.join(tmpdir, "node.crt")
        # ca_path = os.path.join(tmpdir, "ca.crt") # 用于获取中间证书链

        # 将客户端传来的公钥写入临时文件
        with open(pub_key_path, "wb") as f:
            f.write(base64.b64decode(public_key_b64))

        # 使用 Step CLI 基于公钥签发证书
        # --no-password --insecure 用于非交互式环境
        # 注意：需要确保 step CLI 已正确安装并配置
        result = subprocess.run(
            [
                "step",
                "ca",
                "certificate",
                "--pubkey",
                pub_key_path,
                "--no-password",
                "--insecure",
                secure_node_name,
                crt_path,
            ],
            capture_output=True,
            text=True,
            timeout=30, # 设置超时时间
        )
        if result.returncode != 0:
            error_msg = f"证书签发失败: {result.stderr}"
            raise RuntimeError(error_msg)

        # 读取 CA 证书链
        with open(ca_root_path, "rb") as f:
            ca_data = base64.b64encode(f.read()).decode("utf-8")

        with open(crt_path, "rb") as f:
            cert_data = base64.b64encode(f.read()).decode("utf-8")

        return {
            "certificate": cert_data,
            "ca_bundle": ca_data,
        }