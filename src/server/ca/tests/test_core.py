"""
测试 core.py 模块。
"""

import base64
import pytest
from unittest.mock import patch, MagicMock
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from src.server.ca import core


@pytest.fixture
def sample_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

@pytest.fixture
def sample_csr(sample_keys):
    private_key, _ = sample_keys
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'test.example.com'),
    ]))
    csr = builder.sign(private_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem

def test_extract_public_key_from_csr(sample_keys, sample_csr):
    """测试从 CSR 中提取公钥"""
    _, public_key = sample_keys
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64 = base64.b64encode(public_key_pem).decode('utf-8')
    
    csr_b64 = base64.b64encode(sample_csr).decode('utf-8')
    
    extracted_pk_b64 = core.extract_public_key_from_csr(csr_b64)
    assert extracted_pk_b64 == public_key_b64

def test_extract_public_key_from_invalid_csr():
    """测试从无效 CSR 中提取公钥"""
    invalid_csr_b64 = base64.b64encode(b'invalid csr').decode('utf-8')
    with pytest.raises(ValueError, match="无效的 CSR 格式"):
        core.extract_public_key_from_csr(invalid_csr_b64)

@patch('subprocess.run')
def test_issue_certificate_with_step_cli_success(mock_run, sample_csr):
    """测试成功调用 step CLI 签发证书"""
    csr_b64 = base64.b64encode(sample_csr).decode('utf-8')
    secure_node_name = "test_node_name"
    
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result
    
    with patch('os.path.exists', return_value=True):
        with patch('builtins.open', MagicMock()) as mock_open:
            mock_file = MagicMock()
            mock_file.read.return_value = b"fake_cert_data"
            mock_open.return_value.__enter__.return_value = mock_file
            
            result = core.issue_certificate_with_step_cli(secure_node_name, csr_b64)
            
            assert "certificate" in result
            assert "ca_bundle" in result
            mock_run.assert_called_once()
            # 验证调用的是 'sign' 而不是 'certificate'
            assert mock_run.call_args[0][0][2] == 'sign'

@patch('subprocess.run')
def test_issue_certificate_with_step_cli_failure(mock_run, sample_csr):
    """测试调用 step CLI 签发证书失败"""
    csr_b64 = base64.b64encode(sample_csr).decode('utf-8')
    secure_node_name = "test_node_name"
    
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "Error: Failed to sign CSR"
    mock_run.return_value = mock_result
    
    with patch('os.path.exists', return_value=True):
        with pytest.raises(RuntimeError, match="证书签发失败 \(signing CSR\)"):
            core.issue_certificate_with_step_cli(secure_node_name, csr_b64)
