"""
额外的 router.py 模块测试，用于提高测试覆盖率。
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI, HTTPException
from src.server.ca.router import router
from src.server.ca.schemas import ChallengeRequest, IssueRequest

# 创建测试应用
app = FastAPI()
app.include_router(router)
client = TestClient(app)


@patch('src.server.ca.services.request_challenge_service')
def test_request_challenge_internal_error(mock_service):
    """测试 request_challenge 路由处理内部错误"""
    mock_service.side_effect = Exception("Unexpected error")
    
    req_data = {
        "original_node_id": "test-node-id",
        "public_key": "test-public-key"
    }
    
    response = client.post("/ca/request-challenge", json=req_data)
    assert response.status_code == 500
    assert "内部服务器错误" in response.json()["detail"]


@patch('src.server.ca.services.issue_certificate_service')
def test_issue_certificate_validation_error(mock_service):
    """测试 issue_certificate 路由处理验证错误"""
    mock_service.side_effect = ValueError("Invalid challenge")
    
    req_data = {
        "original_node_id": "test-node-id",
        "csr": "test-csr",
        "challenge": "invalid-challenge",
        "signature": "test-signature"
    }
    
    response = client.post("/ca/issue-certificate", json=req_data)
    assert response.status_code == 400
    assert "Invalid challenge" in response.json()["detail"]


@patch('src.server.ca.services.issue_certificate_service')
def test_issue_certificate_runtime_error(mock_service):
    """测试 issue_certificate 路由处理运行时错误"""
    mock_service.side_effect = RuntimeError("Certificate issuance failed")
    
    req_data = {
        "original_node_id": "test-node-id",
        "csr": "test-csr",
        "challenge": "test-challenge",
        "signature": "test-signature"
    }
    
    response = client.post("/ca/issue-certificate", json=req_data)
    assert response.status_code == 500
    assert "证书签发失败" in response.json()["detail"]


@patch('src.server.ca.services.issue_certificate_service')
def test_issue_certificate_internal_error(mock_service):
    """测试 issue_certificate 路由处理内部错误"""
    mock_service.side_effect = Exception("Unexpected error")
    
    req_data = {
        "original_node_id": "test-node-id",
        "csr": "test-csr",
        "challenge": "test-challenge",
        "signature": "test-signature"
    }
    
    response = client.post("/ca/issue-certificate", json=req_data)
    assert response.status_code == 500
    assert "内部服务器错误" in response.json()["detail"]