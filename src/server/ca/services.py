"""
证书签发服务的业务逻辑层。
此模块封装了核心逻辑，提供更清晰的接口供路由层调用。
"""

from . import core
from .schemas import ChallengeRequest, IssueRequest, ChallengeResponse, CertificateResponse


def request_challenge_service(req: ChallengeRequest) -> ChallengeResponse:
    """
    处理请求挑战的业务逻辑。
    :param req: 包含原始节点 ID 和公钥的请求对象。
    :return: 包含挑战的响应对象。
    """
    challenge = core.generate_challenge()
    core.store_challenge(
        challenge,
        {
            "original_node_id": req.original_node_id,
            "public_key": req.public_key,
        },
    )
    return ChallengeResponse(challenge=challenge)


def issue_certificate_service(req: IssueRequest) -> CertificateResponse:
    """
    处理签发证书的业务逻辑。
    :param req: 包含挑战、签名等信息的请求对象。
    :return: 包含证书和 CA 证书链的响应对象。
    :raises ValueError: 如果挑战无效、信息不匹配或签名验证失败。
    :raises RuntimeError: 如果证书签发过程失败。
    """
    # 1. 验证挑战是否存在
    challenge_data = core.get_challenge_data(req.challenge)
    if not challenge_data:
        raise ValueError("无效或过期的挑战")

    # 2. 移除已使用的挑战（防止重用）
    core.remove_challenge(req.challenge)

    # 3. 验证挑战信息是否匹配
    if (
        challenge_data["original_node_id"] != req.original_node_id
        or challenge_data["public_key"] != req.public_key
    ):
        raise ValueError("挑战信息不匹配")

    # 4. 验证签名
    if not core.verify_signature(req.public_key, req.challenge, req.signature):
        raise ValueError("签名验证失败")

    # 5. 生成安全的节点名称
    secure_node_name = core.generate_secure_node_name(
        req.original_node_id, req.public_key
    )

    # 6. 调用核心逻辑签发证书
    cert_data = core.issue_certificate_with_step_cli(
        secure_node_name, req.public_key
    )

    # 7. 返回结果
    return CertificateResponse(
        node_name=secure_node_name,
        certificate=cert_data["certificate"],
        ca_bundle=cert_data["ca_bundle"],
    )