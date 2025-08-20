"""
更多额外的 core.py 模块测试，用于进一步提高测试覆盖率。
"""

import base64
import os
import subprocess
from unittest.mock import patch, MagicMock
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from src.server.ca import core


@patch('src.server.ca.core.logger')
def test_extract_public_key_from_csr_logging(mock_logger):
    """测试 extract_public_key_from_csr 函数中的日志记录"""
    invalid_csr_b64 = base64.b64encode(b"invalid csr").decode('utf-8')
    
    with pytest.raises(ValueError, match="无效的 CSR 格式"):
        core.extract_public_key_from_csr(invalid_csr_b64)
    
    # 验证日志被调用
    mock_logger.error.assert_called_once()


@patch('src.server.ca.core.logger')
@patch('subprocess.run')
def test_issue_certificate_with_step_cli_offline_logging(mock_run, mock_logger):
    """测试 issue_certificate_with_step_cli 函数中离线模式的日志记录"""
    # 创建CSR
    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'test.example.com')])
    ).sign(private_key, hashes.SHA256())
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode('utf-8')
    secure_node_name = "test_node"
    
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result
    
    with patch.dict(os.environ, {"STEP_CA_OFFLINE": "1"}):
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', MagicMock()) as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = b"fake_cert_data"
                mock_open.return_value.__enter__.return_value = mock_file
                
                core.issue_certificate_with_step_cli(secure_node_name, csr_b64)
                
                # 验证日志被调用
                mock_logger.debug.assert_any_call("使用离线模式签发证书 (--offline)")


@patch('src.server.ca.core.logger')
@patch('subprocess.run')
def test_issue_certificate_with_step_cli_online_logging(mock_run, mock_logger):
    """测试 issue_certificate_with_step_cli 函数中在线模式的日志记录"""
    # 创建CSR
    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'test.example.com')])
    ).sign(private_key, hashes.SHA256())
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode('utf-8')
    secure_node_name = "test_node"
    
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result
    
    with patch.dict(os.environ, {"STEP_CA_OFFLINE": "0", "STEP_CA_URL": "https://ca.example.com"}):
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', MagicMock()) as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = b"fake_cert_data"
                mock_open.return_value.__enter__.return_value = mock_file
                
                core.issue_certificate_with_step_cli(secure_node_name, csr_b64)
                
                # 验证日志被调用
                # 检查是否有任何调用包含指定的字符串
                calls = [str(call) for call in mock_logger.debug.call_args_list]
                assert any("使用在线模式签发证书" in call for call in calls)


@patch('src.server.ca.core.logger')
@patch('subprocess.run')
def test_issue_certificate_with_step_cli_command_logging(mock_run, mock_logger):
    """测试 issue_certificate_with_step_cli 函数中命令执行的日志记录"""
    # 创建CSR
    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'test.example.com')])
    ).sign(private_key, hashes.SHA256())
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode('utf-8')
    secure_node_name = "test_node"
    
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result
    
    with patch.dict(os.environ, {"STEP_CA_OFFLINE": "1"}):
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', MagicMock()) as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = b"fake_cert_data"
                mock_open.return_value.__enter__.return_value = mock_file
                
                core.issue_certificate_with_step_cli(secure_node_name, csr_b64)
                
                # 验证命令执行日志被调用
                # 检查是否有任何调用包含指定的字符串
                calls = [str(call) for call in mock_logger.debug.call_args_list]
                assert any("Executing command:" in call for call in calls)


def test_get_dev_ca_dir_coverage():
    """测试 _get_dev_ca_dir 函数的覆盖"""
    # 这个测试主要是为了确保函数被调用，提高覆盖率
    with patch.dict(os.environ, {}, clear=True):
        result = core._get_dev_ca_dir()
        assert result is not None


@patch('src.server.ca.core.logger')
def test_issue_certificate_with_local_ca_logging(mock_logger):
    """测试 issue_certificate_with_local_ca 函数中的日志记录"""
    # 测试CA初始化失败的情况
    with patch('src.server.ca.core._load_or_create_dev_ca', side_effect=Exception("CA init failed")):
        with pytest.raises(RuntimeError, match="开发 CA 初始化失败"):
            core.issue_certificate_with_local_ca("invalid_csr")
        
        # 验证日志被调用
        mock_logger.error.assert_called_once()


@patch('src.server.ca.core._load_or_create_dev_ca')
def test_issue_certificate_with_local_ca_csr_parsing_error(mock_load_ca):
    """测试 issue_certificate_with_local_ca 函数中CSR解析错误"""
    # 模拟CA加载成功
    mock_ca_key = MagicMock()
    mock_ca_cert = MagicMock()
    mock_load_ca.return_value = (mock_ca_key, mock_ca_cert)
    
    # 使用无效的CSR
    invalid_csr_b64 = base64.b64encode(b"invalid csr").decode('utf-8')
    
    with pytest.raises(ValueError, match="无效的 CSR 格式"):
        core.issue_certificate_with_local_ca(invalid_csr_b64)