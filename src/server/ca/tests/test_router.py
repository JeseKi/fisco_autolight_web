"""
测试 router.py 模块。
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from src.server.ca.router import router
from src.server.ca.schemas import ChallengeRequest, IssueRequest


# 创建一个 FastAPI 应用并包含我们的路由
app = FastAPI()
app.include_router(router)

# 创建测试客户端
client = TestClient(app)


def test_request_challenge_endpoint():
    """测试请求挑战端点"""
    req_data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ..."
    }
    
    # Mock service function
    with patch('src.server.ca.services.request_challenge_service') as mock_service:
        mock_response = MagicMock()
        mock_response.challenge = "mocked_challenge_from_service"
        mock_service.return_value = mock_response
        
        response = client.post("/ca/request-challenge", json=req_data)
        
        assert response.status_code == 200
        assert response.json() == {"challenge": "mocked_challenge_from_service"}
        mock_service.assert_called_once_with(ChallengeRequest(**req_data))


def test_request_challenge_endpoint_validation_error():
    """测试请求挑战端点的验证错误"""
    req_data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        # 缺少 public_key
    }
    
    response = client.post("/ca/request-challenge", json=req_data)
    
    assert response.status_code == 422  # Pydantic validation error


def test_issue_certificate_endpoint():
    """测试签发证书端点"""
    req_data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        "challenge": "valid_challenge",
        "signature": "valid_signature_base64"
    }
    
    # Mock service function
    with patch('src.server.ca.services.issue_certificate_service') as mock_service:
        mock_response = MagicMock()
        mock_response.node_name = "secure_node_name"
        mock_response.certificate = "cert_base64"
        mock_response.ca_bundle = "ca_base64"
        mock_service.return_value = mock_response
        
        response = client.post("/ca/issue-certificate", json=req_data)
        
        assert response.status_code == 200
        assert response.json() == {
            "node_name": "secure_node_name",
            "certificate": "cert_base64",
            "ca_bundle": "ca_base64"
        }
        mock_service.assert_called_once_with(IssueRequest(**req_data))


def test_issue_certificate_endpoint_value_error():
    """测试签发证书端点的值错误（如挑战无效）"""
    req_data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        "challenge": "invalid_challenge",
        "signature": "any_signature"
    }
    
    # Mock service function to raise ValueError
    with patch('src.server.ca.services.issue_certificate_service', side_effect=ValueError("无效或过期的挑战")):
        response = client.post("/ca/issue-certificate", json=req_data)
        
        assert response.status_code == 400
        assert response.json() == {"detail": "无效或过期的挑战"}


def test_issue_certificate_endpoint_runtime_error():
    """测试签发证书端点的运行时错误（如签发失败）"""
    req_data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        "challenge": "valid_challenge",
        "signature": "valid_signature"
    }
    
    # Mock service function to raise RuntimeError
    with patch('src.server.ca.services.issue_certificate_service', side_effect=RuntimeError("证书签发失败: Internal error")):
        response = client.post("/ca/issue-certificate", json=req_data)
        
        assert response.status_code == 500
        assert "证书签发失败" in response.json()["detail"]


def test_issue_certificate_endpoint_validation_error():
    """测试签发证书端点的验证错误"""
    req_data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        "challenge": "valid_challenge",
        # 缺少 signature
    }
    
    response = client.post("/ca/issue-certificate", json=req_data)
    
    assert response.status_code == 422  # Pydantic validation error