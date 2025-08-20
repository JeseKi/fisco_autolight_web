"""
验证证书归属公开接口的测试：仅测试公开接口行为，不测试内部实现。
"""

import base64
import os
from typing import Tuple
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch

from src.server.ca import services
from src.server.ca.router import router
from src.server.ca.schemas import VerifyCertificateRequest, VerifyCertificateResponse


def _create_ca_and_issue_cert(tmp_path, subject_cn: str) -> Tuple[str, str]:
    """创建开发 CA 并签发一个证书，返回 (pem_text, pem_base64)。"""
    # 隔离 dev CA 目录
    ca_dir = tmp_path / "dev_ca"
    os.environ["DEV_CA_DIR"] = str(ca_dir)

    # 创建/加载开发 CA
    from src.server.ca import core
    ca_key, ca_cert = core._load_or_create_dev_ca()

    # 生成一把临时私钥并构造证书
    node_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(node_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )

    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    pem_text = pem_bytes.decode("utf-8")
    pem_b64 = base64.b64encode(pem_bytes).decode("utf-8")
    return pem_text, pem_b64


def test_verify_certificate_service_accepts_pem_and_base64(tmp_path, monkeypatch):
    """服务层应同时接受 PEM 文本与 Base64(PEN/DER) 并正确判断归属。"""
    pem_text, pem_b64 = _create_ca_and_issue_cert(tmp_path, subject_cn="node-test")

    # PEM 文本
    resp1 = services.verify_certificate_service(VerifyCertificateRequest(certificate_content=pem_text))
    assert isinstance(resp1, VerifyCertificateResponse)
    assert resp1.is_issued_by_us is True
    assert resp1.subject_common_name == "node-test"

    # Base64 包装
    resp2 = services.verify_certificate_service(VerifyCertificateRequest(certificate_content=pem_b64))
    assert isinstance(resp2, VerifyCertificateResponse)
    assert resp2.is_issued_by_us is True
    assert resp2.subject_common_name == "node-test"


def test_verify_certificate_service_invalid_input():
    """无效输入不抛出异常，返回 is_issued_by_us=False。"""
    resp = services.verify_certificate_service(VerifyCertificateRequest(certificate_content="not-a-cert"))
    assert isinstance(resp, VerifyCertificateResponse)
    assert resp.is_issued_by_us is False
    assert resp.subject_common_name is None
    assert resp.issuer_common_name is None


def test_verify_certificate_route_success():
    """路由层成功返回 200 与验证结果。"""
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    client = TestClient(app)

    req = {"certificate_content": "-----BEGIN CERTIFICATE-----\nMIIB...fake\n-----END CERTIFICATE-----"}

    with patch("src.server.ca.services.verify_certificate_service") as mock_svc:
        mock_svc.return_value = VerifyCertificateResponse(
            is_issued_by_us=True, issuer_common_name="KiSpace Development Root CA", subject_common_name="node-x"
        )
        r = client.post("/v1/ca/verify-certificate", json=req)
        assert r.status_code == 200
        assert r.json() == {
            "is_issued_by_us": True,
            "issuer_common_name": "KiSpace Development Root CA",
            "subject_common_name": "node-x",
        }


def test_verify_certificate_route_internal_error():
    """路由层遇到未预期异常应返回 500。"""
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    client = TestClient(app)

    req = {"certificate_content": "anything"}
    with patch("src.server.ca.services.verify_certificate_service", side_effect=Exception("boom")):
        r = client.post("/v1/ca/verify-certificate", json=req)
        assert r.status_code == 500
        assert "内部服务器错误" in r.json()["detail"]


