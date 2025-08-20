"""
证书签发服务的数据模型定义。
"""

from pydantic import BaseModel


class ChallengeRequest(BaseModel):
    """
    客户端请求挑战时的数据模型。
    """
    original_node_id: str
    public_key: str  # Base64 编码的公钥


class ChallengeResponse(BaseModel):
    """
    服务端返回挑战的数据模型。
    """
    challenge: str


class IssueRequest(BaseModel):
    """
    客户端请求签发证书时的数据模型。
    """
    original_node_id: str
    csr: str  # Base64 编码的证书签名请求 (CSR)
    challenge: str
    signature: str  # Base64 编码的签名


class CertificateResponse(BaseModel):
    """
    服务端返回签发证书的数据模型。
    """
    node_name: str
    certificate: str   # Base64 编码的 node.crt
    ca_bundle: str     # Base64 编码的 ca.crt


class VerifyCertificateRequest(BaseModel):
    """
    客户端请求验证证书归属的数据模型。
    """
    certificate_content: str  # PEM 格式的证书内容


class VerifyCertificateResponse(BaseModel):
    """
    服务端返回证书验证结果的数据模型。
    """
    is_issued_by_us: bool
    issuer_common_name: str | None = None
    subject_common_name: str | None = None