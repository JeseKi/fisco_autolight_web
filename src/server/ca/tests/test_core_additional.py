"""
额外的 core.py 模块测试，用于提高测试覆盖率。
"""

import base64
import os
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from src.server.ca import core


def test_get_dev_ca_dir():
    """测试 _get_dev_ca_dir 函数"""
    # 测试默认情况
    with patch.dict(os.environ, {}, clear=True):
        ca_dir = core._get_dev_ca_dir()
        expected = os.path.join(os.path.dirname(core.__file__), "dev_ca")
        assert ca_dir == expected

    # 测试环境变量设置的情况
    with patch.dict(os.environ, {"DEV_CA_DIR": "/custom/ca/dir"}):
        ca_dir = core._get_dev_ca_dir()
        assert ca_dir == "/custom/ca/dir"


def test_get_dev_ca_paths():
    """测试 _get_dev_ca_paths 函数"""
    with patch.dict(os.environ, {}, clear=True):
        paths = core._get_dev_ca_paths()
        expected_dir = os.path.join(os.path.dirname(core.__file__), "dev_ca")
        assert paths["dir"] == expected_dir
        assert paths["key"] == os.path.join(expected_dir, "ca_key.pem")
        assert paths["cert"] == os.path.join(expected_dir, "ca_cert.pem")
        assert paths["serial"] == os.path.join(expected_dir, "serial.txt")


def test_ensure_dir():
    """测试 _ensure_dir 函数"""
    with tempfile.TemporaryDirectory() as tmpdir:
        new_dir = os.path.join(tmpdir, "new_dir")
        # 目录不存在，应该被创建
        core._ensure_dir(new_dir)
        assert os.path.exists(new_dir)
        assert os.path.isdir(new_dir)

        # 目录已存在，不应该报错
        core._ensure_dir(new_dir)
        assert os.path.exists(new_dir)


def test_load_or_create_dev_ca_existing(tmp_path):
    """测试 _load_or_create_dev_ca 函数加载现有CA"""
    # 创建临时CA文件
    ca_dir = tmp_path / "dev_ca"
    ca_dir.mkdir()
    
    # 生成CA密钥和证书
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = _create_self_signed_cert(ca_key)
    
    # 保存密钥和证书
    key_path = ca_dir / "ca_key.pem"
    cert_path = ca_dir / "ca_cert.pem"
    
    with open(key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    # 测试加载现有CA
    with patch.dict(os.environ, {"DEV_CA_DIR": str(ca_dir)}):
        loaded_key, loaded_cert = core._load_or_create_dev_ca()
        assert loaded_key.private_numbers() == ca_key.private_numbers()
        assert loaded_cert.signature == ca_cert.signature


def test_load_or_create_dev_ca_create_new(tmp_path):
    """测试 _load_or_create_dev_ca 函数创建新CA"""
    ca_dir = tmp_path / "dev_ca"
    
    # 确保目录不存在
    assert not ca_dir.exists()
    
    # 测试创建新CA
    with patch.dict(os.environ, {"DEV_CA_DIR": str(ca_dir)}):
        ca_key, ca_cert = core._load_or_create_dev_ca()
        
        # 验证CA文件已创建
        assert ca_dir.exists()
        assert (ca_dir / "ca_key.pem").exists()
        assert (ca_dir / "ca_cert.pem").exists()
        assert (ca_dir / "serial.txt").exists()
        
        # 验证返回的密钥和证书有效
        assert ca_key is not None
        assert ca_cert is not None


def test_next_serial(tmp_path):
    """测试 _next_serial 函数"""
    ca_dir = tmp_path / "dev_ca"
    ca_dir.mkdir()
    serial_path = ca_dir / "serial.txt"
    
    with patch.dict(os.environ, {"DEV_CA_DIR": str(ca_dir)}):
        # 第一次调用应该返回1
        serial1 = core._next_serial()
        assert serial1 == 1
        
        # 第二次调用应该返回2
        serial2 = core._next_serial()
        assert serial2 == 2
        
        # 验证文件内容
        with open(serial_path, "r") as f:
            content = f.read().strip()
            assert content == "3"


def test_issue_certificate_with_local_ca_invalid_csr():
    """测试 issue_certificate_with_local_ca 函数处理无效CSR"""
    invalid_csr_b64 = base64.b64encode(b"invalid csr").decode('utf-8')
    
    with pytest.raises(ValueError, match="无效的 CSR 格式"):
        core.issue_certificate_with_local_ca(invalid_csr_b64)


def test_issue_certificate_with_local_ca_ca_init_failure(tmp_path):
    """测试 issue_certificate_with_local_ca 函数处理CA初始化失败"""
    ca_dir = tmp_path / "dev_ca"
    
    # 创建一个无法读取的密钥文件来触发异常
    ca_dir.mkdir()
    key_path = ca_dir / "ca_key.pem"
    key_path.touch()
    # 移除读取权限
    os.chmod(key_path, 0o000)
    
    cert_path = ca_dir / "ca_cert.pem"
    cert_path.touch()
    
    # 创建CSR
    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'test.example.com')])
    ).sign(private_key, hashes.SHA256())
    csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode('utf-8')
    
    with patch.dict(os.environ, {"DEV_CA_DIR": str(ca_dir)}):
        with pytest.raises(RuntimeError, match="开发 CA 初始化失败"):
            core.issue_certificate_with_local_ca(csr_b64)


def _create_self_signed_cert(private_key):
    """创建自签名证书的辅助函数"""
    from datetime import datetime, timedelta
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"Test CA"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Test CA"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    return cert