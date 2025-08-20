"""
测试 core.py 模块。
"""

import base64
import pytest
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from src.server.ca import core


@pytest.fixture
def sample_keys():
    """生成一对测试用的 ECDSA 密钥"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem


def test_generate_challenge():
    """测试生成挑战"""
    challenge1 = core.generate_challenge()
    challenge2 = core.generate_challenge()
    assert isinstance(challenge1, str)
    assert isinstance(challenge2, str)
    assert len(challenge1) > 0
    assert len(challenge2) > 0
    assert challenge1 != challenge2  # 极大概率不同


def test_store_and_get_challenge():
    """测试存储和获取挑战"""
    challenge = "test_challenge"
    data = {"original_node_id": "node123", "public_key": "key456"}
    
    core.store_challenge(challenge, data)
    retrieved_data = core.get_challenge_data(challenge)
    
    assert retrieved_data == data
    
    # 清理
    core.remove_challenge(challenge)


def test_remove_challenge():
    """测试移除挑战"""
    challenge = "test_challenge_to_remove"
    data = {"original_node_id": "node123", "public_key": "key456"}
    
    core.store_challenge(challenge, data)
    assert core.get_challenge_data(challenge) == data
    
    core.remove_challenge(challenge)
    assert core.get_challenge_data(challenge) is None


def test_verify_signature_valid(sample_keys):
    """测试验证有效签名"""
    _, public_pem = sample_keys
    public_key_b64 = base64.b64encode(public_pem).decode()
    message = "test message for signing"
    
    # 使用私钥签名
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    signature_b64 = base64.b64encode(signature).decode()
    
    # 验证签名（应该失败，因为不是同一把私钥签的名）
    assert not core.verify_signature(public_key_b64, message, signature_b64)
    
    # 正确地使用对应的私钥签名
    private_key_from_fixture = serialization.load_pem_private_key(sample_keys[0], password=None)
    signature_correct = private_key_from_fixture.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    signature_correct_b64 = base64.b64encode(signature_correct).decode()
    
    # 验证签名（应该成功）
    assert core.verify_signature(public_key_b64, message, signature_correct_b64)


def test_verify_signature_invalid(sample_keys):
    """测试验证无效签名"""
    _, public_pem = sample_keys
    public_key_b64 = base64.b64encode(public_pem).decode()
    message = "test message"
    invalid_signature_b64 = "invalid_base64_signature"
    
    assert not core.verify_signature(public_key_b64, message, invalid_signature_b64)


def test_generate_secure_node_name():
    """测试生成安全节点名称"""
    original_node_id = "0d8a4e0c1f2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d"
    public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa9E...invalid_key_for_test...\n-----END PUBLIC KEY-----"
    public_key_b64 = base64.b64encode(public_key_pem).decode()
    
    node_name1 = core.generate_secure_node_name(original_node_id, public_key_b64)
    node_name2 = core.generate_secure_node_name(original_node_id, public_key_b64)
    
    assert isinstance(node_name1, str)
    assert len(node_name1) == 64  # SHA256 hex digest length
    assert node_name1 == node_name2  # 相同输入应产生相同输出


@patch('subprocess.run')
def test_issue_certificate_with_step_cli_success(mock_run, sample_keys):
    """测试成功调用 step CLI 签发证书"""
    _, public_pem = sample_keys
    public_key_b64 = base64.b64encode(public_pem).decode()
    secure_node_name = "test_node_name"
    
    # 模拟 subprocess.run 的返回值
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = ""
    mock_result.stderr = ""
    mock_run.return_value = mock_result
    
    # 模拟 CA 根证书文件存在
    with patch('os.path.exists', return_value=True):
        with patch('builtins.open', MagicMock()):
            # 模拟读取 CA 证书和签发的证书
            with patch('src.server.ca.core.open', MagicMock()) as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = b"fake_cert_data"
                mock_open.return_value.__enter__.return_value = mock_file
                
                result = core.issue_certificate_with_step_cli(secure_node_name, public_key_b64)
                
                assert "certificate" in result
                assert "ca_bundle" in result
                assert isinstance(result["certificate"], str)
                assert isinstance(result["ca_bundle"], str)


@patch('subprocess.run')
def test_issue_certificate_with_step_cli_failure(mock_run, sample_keys):
    """测试调用 step CLI 签发证书失败"""
    _, public_pem = sample_keys
    public_key_b64 = base64.b64encode(public_pem).decode()
    secure_node_name = "test_node_name"
    
    # 模拟 subprocess.run 返回错误码
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "Error: Failed to issue certificate"
    mock_run.return_value = mock_result
    
    with pytest.raises(RuntimeError, match="证书签发失败"):
        core.issue_certificate_with_step_cli(secure_node_name, public_key_b64)


def test_issue_certificate_with_step_cli_ca_cert_not_found(sample_keys):
    """测试 CA 根证书未找到的情况"""
    _, public_pem = sample_keys
    public_key_b64 = base64.b64encode(public_pem).decode()
    secure_node_name = "test_node_name"
    
    # 模拟 CA 根证书文件不存在
    with patch('os.path.exists', return_value=False):
        with pytest.raises(RuntimeError, match="CA 根证书未找到"):
            core.issue_certificate_with_step_cli(secure_node_name, public_key_b64)