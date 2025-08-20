"""
测试 schemas.py 模块。
"""

import pytest
from pydantic import ValidationError
from src.server.ca.schemas import ChallengeRequest, IssueRequest


def test_challenge_request_valid():
    """测试有效的 ChallengeRequest 数据"""
    data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
    }
    req = ChallengeRequest(**data)
    assert req.original_node_id == data["original_node_id"]
    assert req.public_key == data["public_key"]


def test_challenge_request_missing_field():
    """测试缺少字段的 ChallengeRequest 数据"""
    data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        # 缺少 public_key
    }
    with pytest.raises(ValidationError):
        ChallengeRequest(**data)


def test_issue_request_valid():
    """测试有效的 IssueRequest 数据"""
    data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        "challenge": "random_challenge_string",
        "signature": "Base64EncodedSignature",
    }
    req = IssueRequest(**data)
    assert req.original_node_id == data["original_node_id"]
    assert req.public_key == data["public_key"]
    assert req.challenge == data["challenge"]
    assert req.signature == data["signature"]


def test_issue_request_missing_field():
    """测试缺少字段的 IssueRequest 数据"""
    data = {
        "original_node_id": "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDaXlKVkZ...",
        "challenge": "random_challenge_string",
        # 缺少 signature
    }
    with pytest.raises(ValidationError):
        IssueRequest(**data)