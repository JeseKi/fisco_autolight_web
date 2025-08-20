"""
测试 services.py 模块。
"""

import pytest
from unittest.mock import patch
from src.server.ca import services
from src.server.ca.schemas import ChallengeRequest, IssueRequest, ChallengeResponse, CertificateResponse


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
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        public_key="LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        challenge="valid_challenge",
        signature="valid_signature_base64"
    )
    
    mock_challenge_data = {
        "original_node_id": req.original_node_id,
        "public_key": req.public_key
    }
    
    # Mock core functions
    with patch('src.server.ca.core.get_challenge_data', return_value=mock_challenge_data):
        with patch('src.server.ca.core.remove_challenge') as mock_remove:
            with patch('src.server.ca.core.verify_signature', return_value=True) as mock_verify:
                with patch('src.server.ca.core.generate_secure_node_name', return_value="secure_node_name") as mock_gen_name:
                    with patch('src.server.ca.core.issue_certificate_with_step_cli', return_value={
                        "certificate": "cert_base64",
                        "ca_bundle": "ca_base64"
                    }) as mock_issue:
                        response = services.issue_certificate_service(req)
                        
                        assert isinstance(response, CertificateResponse)
                        assert response.node_name == "secure_node_name"
                        assert response.certificate == "cert_base64"
                        assert response.ca_bundle == "ca_base64"
                        
                        mock_remove.assert_called_once_with(req.challenge)
                        mock_verify.assert_called_once_with(req.public_key, req.challenge, req.signature)
                        mock_gen_name.assert_called_once_with(req.original_node_id, req.public_key)
                        mock_issue.assert_called_once_with("secure_node_name", req.public_key)


def test_issue_certificate_service_invalid_challenge():
    """测试无效挑战的签发证书服务"""
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        public_key="LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        challenge="invalid_challenge",
        signature="any_signature"
    )
    
    # Mock core function to return None for invalid challenge
    with patch('src.server.ca.core.get_challenge_data', return_value=None):
        with pytest.raises(ValueError, match="无效或过期的挑战"):
            services.issue_certificate_service(req)


def test_issue_certificate_service_mismatched_data():
    """测试挑战信息不匹配的签发证书服务"""
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        public_key="LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        challenge="valid_challenge",
        signature="any_signature"
    )
    
    # Mock challenge data that doesn't match the request
    mock_challenge_data = {
        "original_node_id": "different_node_id",
        "public_key": "different_public_key"
    }
    
    with patch('src.server.ca.core.get_challenge_data', return_value=mock_challenge_data):
        with patch('src.server.ca.core.remove_challenge') as mock_remove:
            with pytest.raises(ValueError, match="挑战信息不匹配"):
                services.issue_certificate_service(req)
            mock_remove.assert_called_once_with(req.challenge)


def test_issue_certificate_service_invalid_signature():
    """测试签名验证失败的签发证书服务"""
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        public_key="LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        challenge="valid_challenge",
        signature="invalid_signature"
    )
    
    mock_challenge_data = {
        "original_node_id": req.original_node_id,
        "public_key": req.public_key
    }
    
    with patch('src.server.ca.core.get_challenge_data', return_value=mock_challenge_data):
        with patch('src.server.ca.core.remove_challenge') as mock_remove:
            with patch('src.server.ca.core.verify_signature', return_value=False) as mock_verify:
                with pytest.raises(ValueError, match="签名验证失败"):
                    services.issue_certificate_service(req)
                mock_remove.assert_called_once_with(req.challenge)
                mock_verify.assert_called_once_with(req.public_key, req.challenge, req.signature)


@patch('src.server.ca.core.get_challenge_data', return_value={"original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d", "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ..."})
@patch('src.server.ca.core.remove_challenge')
@patch('src.server.ca.core.verify_signature', return_value=True)
@patch('src.server.ca.core.generate_secure_node_name', return_value="node_name")
def test_issue_certificate_service_core_error(mock_gen_name, mock_verify, mock_remove, mock_get_data):
    """测试核心逻辑错误的签发证书服务"""
    req = IssueRequest(
        original_node_id="0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        public_key="LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        challenge="valid_challenge",
        signature="valid_signature"
    )
    
    # Mock core function to raise an exception
    with patch('src.server.ca.core.issue_certificate_with_step_cli', side_effect=RuntimeError("Internal error")):
        with pytest.raises(RuntimeError, match="Internal error"):
            services.issue_certificate_service(req)