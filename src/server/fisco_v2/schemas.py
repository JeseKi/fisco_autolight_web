"""
文件功能：
    定义 FISCO 节点管理相关的公开数据模型（Pydantic）。

公开接口：
    - NodeStatus: 节点状态数据模型

内部方法：
    无

公开接口的 Pydantic 模型：
    - NodeStatus
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class NodeStatus(BaseModel):
    """节点运行状态。"""

    initialized: bool = Field(description="是否已初始化（证书/配置/目录已就绪）")
    running: bool = Field(description="是否正在运行")
    pid: int | None = Field(default=None, description="运行中的进程 PID")
    base_dir: str = Field(description="节点的运行基目录")
    p2p_port: int = Field(description="P2P 端口")
    rpc_port: int = Field(description="RPC 端口")