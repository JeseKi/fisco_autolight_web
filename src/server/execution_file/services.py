from typing import List

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
    
def get_lightnode_genesis() -> str:
    """
    获取 lightnode 创世文件。
    """
    with open(Path.cwd() / "src/server/fisco_v2/nodes/127.0.0.1/node0/config.genesis", "r") as f:
        return f.read()
    
def get_nodes_config() -> List[str]:
    """
    获取 nodes 配置。
    """
    return config.nodes

def get_lightnode_ezdeploy(platform: Platform) -> str:
    """
    获取 lightnode 部署文件。
    """
    if platform == Platform.LINUX:
        return config.linux_lightnode_ezdeploy_url
    elif platform == Platform.MACOS:
        return config.mac_lightnode_ezdeploy_url
    else:
        raise ValueError(f"不支持的平台: {platform}")