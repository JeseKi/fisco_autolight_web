"""
节点状态管理服务。

提供节点状态查询和确保节点启动的接口。
"""

from __future__ import annotations

from loguru import logger
import os

from ..schemas import NodeStatus

from .node_setup import (
    _ensure_dirs,
    _is_build_chain_layout,
    _parse_ports_from_config,
    _get_env_int,
    _write_config_if_absent,
    _write_nodes_if_absent,
    _generate_key_and_cert,
    _ensure_consensus_key_and_genesis,
    _paths
)
from .node_process import start_node, get_node_status


def status() -> NodeStatus:
    """获取节点状态。"""
    return get_node_status()


def ensure_started() -> NodeStatus:
    """确保节点已初始化并运行。"""
    _ensure_dirs()
    base = _paths()["base"]
    build_chain_mode = _is_build_chain_layout(base)
    if build_chain_mode:
        # 复用现有 config.ini 与 config.genesis，不生成我们自己的创世与配置
        p2p_port, rpc_port = _parse_ports_from_config(base / "config.ini")
        # 仅在缺失 TLS 时生成（不会动 node.pem 与 genesis）
        try:
            _generate_key_and_cert()
        except Exception as e:
            logger.warning(f"TLS 证书生成失败（可忽略，若已存在）：{e}")
    else:
        p2p_port = _get_env_int("FISCO_P2P_PORT", 30300)
        rpc_port = _get_env_int("FISCO_RPC_PORT", 20200)
        _write_config_if_absent(p2p_port=p2p_port, rpc_port=rpc_port)
        _write_nodes_if_absent()
        _generate_key_and_cert()
        # 在启动前确保共识私钥与创世文件存在
        try:
            _ensure_consensus_key_and_genesis(os.environ.get("FISCO_GROUP_ID", "group0"))
        except Exception as e:
            logger.warning(f"共识密钥/创世文件准备失败：{e}")

    return start_node()