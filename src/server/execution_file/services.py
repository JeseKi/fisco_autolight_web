from .schemas import Platform
from ..config import config
from pathlib import Path

def get_execution_file_url(platform: Platform) -> str:
    """
    获取执行文件的 URL。
    :return: 执行文件的 URL。
    """
    if platform == Platform.LINUX:
        return config.linux_execution_file_url
    elif platform == Platform.MACOS:
        return config.macos_execution_file_url
    elif platform == Platform.WINDOWS:
        return config.windows_execution_file_url
    else:
        raise ValueError(f"不支持的平台: {platform}")
    
def get_lightnode_config() -> str:
    """
    获取 lightnode 配置。
    """
    with open(Path.cwd() / "assets" / "config.ini", "r") as f:
        return f.read()