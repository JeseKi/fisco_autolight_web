
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
    challenge_data = core.get_challenge_data(req.challenge)
    if not challenge_data:
        raise ValueError("无效或过期的挑战")

    core.remove_challenge(req.challenge)

    # 验证 CSR 中的公钥是否与请求挑战时的公钥一致
    # 这一步在当前的设计中是必要的，以确保 CSR 是由持有对应私钥的客户端生成的
    public_key_from_csr_b64 = core.extract_public_key_from_csr(req.csr)
    if challenge_data["public_key"] != public_key_from_csr_b64:
        raise ValueError("CSR 中的公钥与请求挑战时的公钥不匹配")
    
    # 使用请求挑战时的公钥来验证签名
    if not core.verify_signature(challenge_data["public_key"], req.challenge, req.signature):
        raise ValueError("签名验证失败")

    # 生成安全的节点名称，用作证书的 Common Name
    secure_node_name = core.generate_secure_node_name(
        req.original_node_id, challenge_data["public_key"]
    )

    # 使用本地开发 CA 签发证书
    cert_data = core.issue_certificate_with_local_ca(req.csr)

    return CertificateResponse(
        node_name=secure_node_name,
        certificate=cert_data["certificate"],
        ca_bundle=cert_data["ca_bundle"],
    )