"""
控制台部署服务测试。
"""

import tempfile
from pathlib import Path
from src.server.fisco_v2.services.console_deploy import deploy_console, is_console_ready, _update_console_config_port


def test_deploy_console():
    """测试控制台部署功能。"""
    # 测试函数是否可以导入
    assert callable(deploy_console)
    assert callable(is_console_ready)
    
    # 测试控制台是否就绪
    ready = is_console_ready()
    assert isinstance(ready, bool)


def test_update_console_config_port():
    """测试端口更新功能。"""
    # 创建临时配置文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[network]
peers=["127.0.0.1:20200", "127.0.0.1:20201"]
''')
        temp_path = Path(f.name)
    
    try:
        # 更新端口
        _update_console_config_port(temp_path, 30300)
        
        # 检查内容是否正确更新
        content = temp_path.read_text()
        assert '127.0.0.1:30300' in content
        assert '127.0.0.1:20200' not in content
    finally:
        # 清理临时文件
        temp_path.unlink()


if __name__ == "__main__":
    test_deploy_console()
    test_update_console_config_port()
    print("所有测试通过")