"""
针对证书签发服务公开接口的测试：仅测试公开接口行为，不测试内部实现。
"""

import base64
from typing import Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.server.ca import services
from src.server.ca.schemas import (
    ChallengeRequest,
    IssueRequest,
)

from unittest.mock import patch
from src.server.ca.schemas import ChallengeResponse, CertificateResponse



def _gen_key_and_csr(common_name: str) -> Tuple[str, str]:
    """生成 EC 私钥与 CSR（返回 base64 编码的公钥与 CSR PEM）。"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_b64 = base64.b64encode(public_key_pem).decode("utf-8")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_b64 = base64.b64encode(csr_pem).decode("utf-8")
    return public_key_b64, csr_b64


def _sign_message(private_key: ec.EllipticCurvePrivateKey, message: str) -> str:
    sig = private_key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode("utf-8")


def test_full_happy_path(tmp_path, monkeypatch):
    # 生成密钥对与 CSR
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_b64 = base64.b64encode(public_key_pem).decode("utf-8")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "node-1")])
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode("utf-8")

    # 隔离 dev CA 目录
    ca_dir = tmp_path / "dev_ca"
    monkeypatch.setenv("DEV_CA_DIR", str(ca_dir))

    # 步骤1：请求挑战
    req_ch = ChallengeRequest(original_node_id="nodeid-1", public_key=public_key_b64)
    resp_ch = services.request_challenge_service(req_ch)

    # 步骤2：签名挑战并请求签发
    signature_b64 = _sign_message(private_key, resp_ch.challenge)
    req_issue = IssueRequest(
        original_node_id="nodeid-1",
        csr=csr_b64,
        challenge=resp_ch.challenge,
        signature=signature_b64,
    )
    resp_cert = services.issue_certificate_service(req_issue)

    assert resp_cert.node_name
    assert resp_cert.certificate
    assert resp_cert.ca_bundle


def test_csr_pubkey_mismatch(tmp_path, monkeypatch):
    # 生成两把不同的钥
    k1 = ec.generate_private_key(ec.SECP256R1())
    k2 = ec.generate_private_key(ec.SECP256R1())
    pub1_b64 = base64.b64encode(
        k1.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("utf-8")

    csr2 = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "node-2")]))
        .sign(k2, hashes.SHA256())
    )
    csr2_b64 = base64.b64encode(csr2.public_bytes(serialization.Encoding.PEM)).decode("utf-8")

    ca_dir = tmp_path / "dev_ca"
    monkeypatch.setenv("DEV_CA_DIR", str(ca_dir))

    resp_ch = services.request_challenge_service(
        ChallengeRequest(original_node_id="nodeid-2", public_key=pub1_b64)
    )
    sig_b64 = base64.b64encode(k1.sign(resp_ch.challenge.encode("utf-8"), ec.ECDSA(hashes.SHA256()))).decode("utf-8")

    with pytest.raises(ValueError) as ei:
        services.issue_certificate_service(
            IssueRequest(
                original_node_id="nodeid-2",
                csr=csr2_b64,
                challenge=resp_ch.challenge,
                signature=sig_b64,
            )
        )
    assert "CSR 中的公钥与请求挑战时的公钥不匹配" in str(ei.value)


def test_invalid_signature(tmp_path, monkeypatch):
    k = ec.generate_private_key(ec.SECP256R1())
    pub_b64 = base64.b64encode(
        k.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("utf-8")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "node-3")]))
        .sign(k, hashes.SHA256())
    )
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode("utf-8")

    ca_dir = tmp_path / "dev_ca"
    monkeypatch.setenv("DEV_CA_DIR", str(ca_dir))

    resp_ch = services.request_challenge_service(
        ChallengeRequest(original_node_id="nodeid-3", public_key=pub_b64)
    )
    # 伪造签名
    bad_sig_b64 = base64.b64encode(b"bad").decode("utf-8")

    with pytest.raises(ValueError) as ei:
        services.issue_certificate_service(
            IssueRequest(
                original_node_id="nodeid-3",
                csr=csr_b64,
                challenge=resp_ch.challenge,
                signature=bad_sig_b64,
            )
        )
    assert "签名验证失败" in str(ei.value)


def test_invalid_challenge():
    # 无效或过期挑战
    with pytest.raises(ValueError) as ei:
        services.issue_certificate_service(
            IssueRequest(
                original_node_id="nodeid-x",
                csr="AAAA",
                challenge="not-exists",
                signature="AAAA",
            )
        )
    assert "无效或过期的挑战" in str(ei.value)

def test_request_challenge_service():
    """测试请求挑战服务"""
    req = ChallengeRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        public_key="LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ..."
    )
    
    # Mock core functions
    with patch('src.server.ca.core.generate_challenge', return_value="mocked_challenge"):
        with patch('src.server.ca.core.store_challenge') as mock_store:
            response = services.request_challenge_service(req)
            
            assert isinstance(response, ChallengeResponse)
            assert response.challenge == "mocked_challenge"
            mock_store.assert_called_once_with("mocked_challenge", {
                "original_node_id": req.original_node_id,
                "public_key": req.public_key
            })


def test_issue_certificate_service_success():
    """测试成功签发证书服务"""
    # 生成有效的密钥对和CSR用于测试
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_b64 = base64.b64encode(public_key_pem).decode("utf-8")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test-node")])
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode("utf-8")
    
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        csr=csr_b64,  # 使用有效的CSR
        challenge="valid_challenge",
        signature="valid_signature_base64"
    )
    
    mock_challenge_data = {
        "original_node_id": req.original_node_id,
        "public_key": public_key_b64  # 使用与CSR匹配的公钥
    }
    
    # Mock core functions
    with patch('src.server.ca.core.get_challenge_data', return_value=mock_challenge_data):
        with patch('src.server.ca.core.remove_challenge') as mock_remove:
            # Mock extract_public_key_from_csr to return the same public key as in challenge_data
            with patch('src.server.ca.core.extract_public_key_from_csr', return_value=mock_challenge_data["public_key"]) as mock_extract:
                with patch('src.server.ca.core.verify_signature', return_value=True) as mock_verify:
                    with patch('src.server.ca.core.generate_secure_node_name', return_value="secure_node_name") as mock_gen_name:
                        with patch('src.server.ca.core.issue_certificate_with_local_ca', return_value={
                            "certificate": "cert_base64",
                            "ca_bundle": "ca_base64"
                        }) as mock_issue:
                            response = services.issue_certificate_service(req)
                            
                            assert isinstance(response, CertificateResponse)
                            assert response.node_name == "secure_node_name"
                            assert response.certificate == "cert_base64"
                            assert response.ca_bundle == "ca_base64"
                            
                            mock_remove.assert_called_once_with(req.challenge)
                            mock_extract.assert_called_once_with(req.csr)
                            mock_verify.assert_called_once_with(mock_challenge_data["public_key"], req.challenge, req.signature)
                            mock_gen_name.assert_called_once_with(req.original_node_id, mock_challenge_data["public_key"])
                            mock_issue.assert_called_once_with(req.csr)


def test_issue_certificate_service_invalid_challenge():
    """测试无效挑战的签发证书服务"""
    # 生成有效的密钥对和CSR用于测试
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _ = base64.b64encode(public_key_pem).decode("utf-8")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test-node")])
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode("utf-8")
    
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        csr=csr_b64,  # 使用有效的CSR
        challenge="invalid_challenge",
        signature="any_signature"
    )
    
    # Mock core function to return None for invalid challenge
    with patch('src.server.ca.core.get_challenge_data', return_value=None):
        with pytest.raises(ValueError, match="无效或过期的挑战"):
            services.issue_certificate_service(req)


def test_issue_certificate_service_mismatched_data():
    """测试挑战信息不匹配的签发证书服务"""
    # 生成有效的密钥对和CSR用于测试
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _ = base64.b64encode(public_key_pem).decode("utf-8")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test-node")])
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode("utf-8")
    
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        csr=csr_b64,  # 使用有效的CSR
        challenge="valid_challenge",
        signature="any_signature"
    )
    
    # Mock challenge data 
    mock_challenge_data = {
        "original_node_id": req.original_node_id,
        "public_key": "public_key_from_challenge" # Public key stored during challenge request
    }
    
    with patch('src.server.ca.core.get_challenge_data', return_value=mock_challenge_data):
        with patch('src.server.ca.core.remove_challenge') as mock_remove:
            # Mock extract_public_key_from_csr to return a different public key
            with patch('src.server.ca.core.extract_public_key_from_csr', return_value="public_key_from_csr") as mock_extract:
                with pytest.raises(ValueError, match="CSR 中的公钥与请求挑战时的公钥不匹配"):
                    services.issue_certificate_service(req)
                mock_extract.assert_called_once_with(req.csr)
            mock_remove.assert_called_once_with(req.challenge)


def test_issue_certificate_service_invalid_signature():
    """测试签名验证失败的签发证书服务"""
    # 生成有效的密钥对和CSR用于测试
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_b64 = base64.b64encode(public_key_pem).decode("utf-8")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test-node")])
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode("utf-8")
    
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        csr=csr_b64,  # 使用有效的CSR
        challenge="valid_challenge",
        signature="invalid_signature"
    )
    
    mock_challenge_data = {
        "original_node_id": req.original_node_id,
        "public_key": public_key_b64  # 使用与CSR匹配的公钥
    }
    
    with patch('src.server.ca.core.get_challenge_data', return_value=mock_challenge_data):
        with patch('src.server.ca.core.remove_challenge') as mock_remove:
            # Mock extract_public_key_from_csr to return the same public key as in challenge_data
            with patch('src.server.ca.core.extract_public_key_from_csr', return_value=mock_challenge_data["public_key"]) as mock_extract:
                with patch('src.server.ca.core.verify_signature', return_value=False) as mock_verify:
                    with pytest.raises(ValueError, match="签名验证失败"):
                        services.issue_certificate_service(req)
                    mock_remove.assert_called_once_with(req.challenge)
                    mock_extract.assert_called_once_with(req.csr)
                    mock_verify.assert_called_once_with(mock_challenge_data["public_key"], req.challenge, req.signature)


def test_issue_certificate_service_core_error():
    """测试核心逻辑错误的签发证书服务"""
    # 生成有效的密钥对和CSR用于测试
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_b64 = base64.b64encode(public_key_pem).decode("utf-8")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test-node")])
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode("utf-8")
    
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        csr=csr_b64,  # 使用有效的CSR
        challenge="valid_challenge",
        signature="valid_signature"
    )
    
    # Mock core functions
    with patch('src.server.ca.core.get_challenge_data', return_value={"original_node_id": req.original_node_id, "public_key": public_key_b64}):
        with patch('src.server.ca.core.remove_challenge'):
            with patch('src.server.ca.core.verify_signature', return_value=True):
                with patch('src.server.ca.core.generate_secure_node_name', return_value="node_name"):
                    # Mock core function to raise an exception
                    with patch('src.server.ca.core.extract_public_key_from_csr', return_value=public_key_b64) as mock_extract:
                        with patch('src.server.ca.core.issue_certificate_with_local_ca', side_effect=RuntimeError("Internal error")):
                            with pytest.raises(RuntimeError, match="Internal error"):
                                services.issue_certificate_service(req)
                            mock_extract.assert_called_once_with(req.csr)
