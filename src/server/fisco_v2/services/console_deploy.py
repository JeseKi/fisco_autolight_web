"""
控制台部署服务 (v2)。

负责配置和部署 FISCO 控制台。
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
import re

from loguru import logger
from src.server.fisco_v2.services.node_setup import _get_code_dir, _get_build_chain_layout_paths


def _get_console_dir() -> Path:
    """获取控制台目录。"""
    code_dir = _get_code_dir()
    return code_dir / "console"


def _ensure_console_exists() -> None:
    """确保控制台目录存在。"""
    console_dir = _get_console_dir()
    if not console_dir.exists():
        raise RuntimeError(f"控制台目录不存在: {console_dir}")


def _is_console_configured() -> bool:
    """检查控制台是否已配置。"""
    console_dir = _get_console_dir()
    config_file = console_dir / "conf" / "config.toml"
    return config_file.exists()


def _get_console_config_paths() -> dict[str, Path]:
    """获取控制台配置路径。"""
    console_dir = _get_console_dir()
    return {
        "base": console_dir,
        "conf": console_dir / "conf",
        "config_example": console_dir / "conf" / "config-example.toml",
        "config": console_dir / "conf" / "config.toml",
    }


def deploy_console(rpc_port: int = 20200) -> None:
    """部署控制台。
    
    1. 拷贝配置文件
    2. 替换配置文件中的默认端口（如果节点未使用默认端口）
    3. 拷贝节点SDK证书到控制台配置目录
    """
    # 确保控制台存在
    _ensure_console_exists()
    
    # 获取路径
    console_paths = _get_console_config_paths()
    node_paths = _get_build_chain_layout_paths()
    
    # 1. 拷贝配置文件
    config_example = console_paths["config_example"]
    config_target = console_paths["config"]
    
    if not config_target.exists():
        logger.info(f"拷贝控制台配置文件: {config_example} -> {config_target}")
        shutil.copy2(config_example, config_target)
    else:
        logger.info("控制台配置文件已存在")
    
    # 2. 替换配置文件中的默认端口
    if rpc_port != 20200:
        logger.info(f"更新配置文件中的RPC端口为: {rpc_port}")
        _update_console_config_port(config_target, rpc_port)
    else:
        logger.info("使用默认RPC端口: 20200")
    
    # 3. 拷贝节点SDK证书到控制台配置目录
    logger.info("拷贝节点SDK证书到控制台配置目录")
    _copy_all_sdk_files(node_paths, console_paths)
    
    logger.info("控制台部署完成")


def _update_console_config_port(config_path: Path, rpc_port: int) -> None:
    """更新控制台配置文件中的RPC端口。"""
    try:
        # 读取配置文件内容
        content = config_path.read_text(encoding="utf-8")
        
        # 使用正则表达式替换端口号
        # 匹配 peers 数组中的 127.0.0.1:20200
        updated_content = re.sub(
            r'"127\.0\.0\.1:20200"', 
            f'"127.0.0.1:{rpc_port}"', 
            content
        )
        
        # 写回文件
        config_path.write_text(updated_content, encoding="utf-8")
        logger.info(f"已更新控制台配置文件中的端口为: {rpc_port}")
        
    except Exception as e:
        logger.error(f"更新控制台配置文件端口时出错: {str(e)}")
        raise RuntimeError(f"更新控制台配置文件端口时出错: {str(e)}")


def _copy_all_sdk_files(node_paths: dict[str, Path], console_paths: dict[str, Path]) -> None:
    """拷贝节点SDK目录下所有文件到控制台配置目录。"""
    try:
        # 确保目标目录存在
        console_conf_dir = console_paths["conf"]
        console_conf_dir.mkdir(parents=True, exist_ok=True)
        
        # SDK源目录
        sdk_dir = node_paths["sdk_dir"]
        if not sdk_dir.exists():
            raise RuntimeError(f"节点SDK目录不存在: {sdk_dir}")
        
        # 拷贝SDK目录下所有文件
        logger.info(f"拷贝SDK目录下所有文件: {sdk_dir} -> {console_conf_dir}")
        for item in sdk_dir.iterdir():
            if item.is_file():
                dst_path = console_conf_dir / item.name
                logger.info(f"拷贝文件: {item} -> {dst_path}")
                shutil.copy2(item, dst_path)
        
    except Exception as e:
        logger.error(f"拷贝SDK文件时出错: {str(e)}")
        raise RuntimeError(f"拷贝SDK文件时出错: {str(e)}")


def is_console_ready() -> bool:
    """检查控制台是否已准备就绪。"""
    try:
        # 检查控制台目录是否存在
        _ensure_console_exists()
        
        # 检查配置文件是否存在
        if not _is_console_configured():
            return False
            
        # 检查证书文件是否存在
        console_paths = _get_console_config_paths()
        console_conf_dir = console_paths["conf"]
        
        required_certs = ["ca.crt", "ssl.crt", "ssl.key"]
        for cert in required_certs:
            if not (console_conf_dir / cert).exists():
                return False
                
        return True
    except Exception:
        return False