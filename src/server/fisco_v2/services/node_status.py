"""
节点状态管理服务 (v2)。

提供节点状态查询和确保节点启动的接口，专门用于通过 build_chain.sh 创建的节点。
"""

from __future__ import annotations

from loguru import logger
import json

from ..schemas import NodeStatus
from .node_setup import (
    _ensure_build_chain_sh,
    _is_build_chain_layout_ready,
    _run_build_chain_sh,
    _get_env_int,
    overwrite_tls_with_internal_ca,
    overwrite_sdk_tls_with_internal_ca,
    download_console,
)
from .console_deploy import deploy_console
from .contract_counter import ensure_counter_deployed_and_increment, is_counter_initialized
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
    
    # 下载控制台（如果不存在）
    try:
        from .console_deploy import _get_console_dir
        console_dir = _get_console_dir()
        if not console_dir.exists():
            download_console()
        else:
            logger.info("控制台目录已存在，跳过下载")
    except Exception as e:
        logger.warning(f"下载控制台失败：{e}")
    
    # 使用内部 CA 覆盖 TLS（总是覆盖，确保统一）
    try:
        overwrite_tls_with_internal_ca()
    except Exception as e:
        logger.warning(f"覆盖 TLS 失败：{e}")
    # 同步覆盖 SDK 侧 TLS
    try:
        overwrite_sdk_tls_with_internal_ca()
    except Exception as e:
        logger.warning(f"覆盖 SDK TLS 失败：{e}")

    # 启动节点
    s = start_node()
    
    # 部署控制台（在节点启动后）
    try:
        rpc_port = _get_env_int("FISCO_RPC_PORT", 20200)
        deploy_console(rpc_port)
    except Exception as e:
        logger.warning(f"部署控制台失败：{e}")

    # 合约初始化与一次 increment 调用（幂等：通过是否存在 Counter.sol 判断是否已初始化）
    try:
        if not is_counter_initialized():
            r = ensure_counter_deployed_and_increment()
            if not r.deploy_success or not r.increment_sent:
                logger.warning(f"合约初始化或调用可能失败：{json.dumps(r.model_dump(), ensure_ascii=False)}")
        else:
            # 已初始化，也尝试一次调用，确保链上交互按预期
            r = ensure_counter_deployed_and_increment()
            if not r.increment_sent:
                logger.warning(f"已初始化但调用失败：{json.dumps(r.model_dump(), ensure_ascii=False)}")
    except Exception as e:
        logger.warning(f"合约初始化流程失败：{e}")

    return s