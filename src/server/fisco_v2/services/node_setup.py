"""
节点初始化与配置服务 (v2)。

负责通过 build_chain.sh 脚本创建和管理 FISCO 节点。
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from loguru import logger


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def _get_code_dir() -> Path:
    """获取代码目录。"""
    return Path(__file__).resolve().parent.parent


def _get_build_chain_sh_path() -> Path:
    """获取 build_chain.sh 脚本路径。"""
    code_dir = _get_code_dir()
    return code_dir / "build_chain.sh"


def _ensure_build_chain_sh() -> None:
    """确保 build_chain.sh 脚本存在。"""
    sh_path = _get_build_chain_sh_path()
    if not sh_path.exists():
        raise RuntimeError(f"找不到 build_chain.sh 脚本: {sh_path}")


def _get_default_node_path() -> Path:
    """获取默认节点路径。"""
    code_dir = _get_code_dir()
    return code_dir / "nodes" / "127.0.0.1" / "node0"


def _is_build_chain_layout_ready() -> bool:
    """检查是否已经通过 build_chain.sh 创建了节点布局。"""
    node_path = _get_default_node_path()
    config_ini = node_path / "config.ini"
    config_genesis = node_path / "config.genesis"
    start_sh = node_path / "start.sh"
    
    return node_path.exists() and config_ini.exists() and config_genesis.exists() and start_sh.exists()


def _get_build_chain_layout_paths() -> dict[str, Path]:
    """获取 build_chain 产出的节点布局路径。"""
    base = _get_default_node_path()
    return {
        "base": base,
        "conf": base / "conf",
        "data": base / "data",
        "log": base / "log",
        "config_ini": base / "config.ini",
        "nodes_json": base / "nodes.json",
        "ssl_key": base / "conf" / "ssl.key",
        "ssl_crt": base / "conf" / "ssl.crt",
        "ca_crt": base / "conf" / "ca.crt",
        "pid": base / "node.pid",
        "status": base / "node_status.json",
    }


def _run_build_chain_sh(p2p_port: int, rpc_port: int) -> None:
    """运行 build_chain.sh 脚本创建节点。"""
    code_dir = _get_code_dir()
    sh_path = _get_build_chain_sh_path()
    
    # 确保脚本有执行权限
    sh_path.chmod(0o755)
    
    # 构建命令
    cmd = ["bash", str(sh_path), "-l", "127.0.0.1:1", "-p", f"{p2p_port},{rpc_port}"]
    
    logger.info(f"执行 build_chain.sh：{' '.join(cmd)}")
    
    try:
        # 运行 build_chain.sh
        result = subprocess.run(
            cmd,
            cwd=str(code_dir),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        logger.info(f"build_chain.sh 执行成功: {result.stdout}")
        
        # 检查节点目录是否创建成功
        if not _is_build_chain_layout_ready():
            raise RuntimeError("build_chain.sh 执行完成，但节点目录未正确创建")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"build_chain.sh 执行失败: {e.stderr}")
        raise RuntimeError(f"build_chain.sh 执行失败: {e.stderr}")
    except Exception as e:
        logger.error(f"运行 build_chain.sh 时发生未知错误: {str(e)}")
        raise RuntimeError(f"运行 build_chain.sh 时发生未知错误: {str(e)}")