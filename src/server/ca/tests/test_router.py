
"""
测试 router.py 模块。
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from src.server.ca.router import router
from src.server.ca.schemas import ChallengeRequest, IssueRequest


app = FastAPI()
app.include_router(router, prefix="/v1")

client = TestClient(app)


def test_issue_certificate_endpoint_csr():
    """测试签发证书端点 (CSR 模式)"""
    req_data = {
        "original_node_id": "node123",
        "csr": "csr_base64_string",
        "challenge": "valid_challenge",
        "signature": "valid_signature_base64"
    }
    
    with patch('src.server.ca.services.issue_certificate_service') as mock_service:
        mock_response = MagicMock()
        mock_response.node_name = "secure_node_name"
        mock_response.certificate = "cert_base64"
        mock_response.ca_bundle = "ca_base64"
        mock_service.return_value = mock_response
        
        response = client.post("/v1/ca/issue-certificate", json=req_data)
        
        assert response.status_code == 200
        assert response.json() == {
            "node_name": "secure_node_name",
            "certificate": "cert_base64",
            "ca_bundle": "ca_base64"
        }
        mock_service.assert_called_once_with(IssueRequest(**req_data))

def test_issue_certificate_endpoint_validation_error_csr():
    """测试签发证书端点的验证错误 (CSR 模式)"""
    req_data = {
        "original_node_id": "node123",
        "challenge": "valid_challenge",
        "signature": "valid_signature_base64"
        # 缺少 csr
    }
    
    response = client.post("/v1/ca/issue-certificate", json=req_data)
    
    assert response.status_code == 422
