"""
节点状态管理服务 (v2)。

提供节点状态查询和确保节点启动的接口，专门用于通过 build_chain.sh 创建的节点。
"""

from __future__ import annotations

from loguru import logger
import os

from ..schemas import NodeStatus
from .node_setup import (
    _ensure_build_chain_sh,
    _get_build_chain_layout_paths,
    _is_build_chain_layout_ready,
    _run_build_chain_sh,
    _get_env_int,
    overwrite_tls_with_internal_ca,
)
from .node_process import start_node, get_node_status


def status() -> NodeStatus:
    """获取节点状态。"""
    return get_node_status()


def ensure_started() -> NodeStatus:
    """确保节点已初始化并运行。"""
    # 检查 build_chain.sh 是否存在
    _ensure_build_chain_sh()
    
    # 检查是否已经通过 build_chain.sh 创建了节点
    if not _is_build_chain_layout_ready():
        # 如果没有，则运行 build_chain.sh 创建节点
        p2p_port = _get_env_int("FISCO_P2P_PORT", 30300)
        rpc_port = _get_env_int("FISCO_RPC_PORT", 20200)
        _run_build_chain_sh(p2p_port, rpc_port)
    
    # 使用内部 CA 覆盖 TLS（总是覆盖，确保统一）
    try:
        overwrite_tls_with_internal_ca()
    except Exception as e:
        logger.warning(f"覆盖 TLS 失败：{e}")

    # 启动节点
    return start_node()