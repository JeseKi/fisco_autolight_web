"""
文件功能：
    定义 FISCO 节点管理相关的公开数据模型（Pydantic）。

公开接口：
    - NodeStatus: 节点状态数据模型
    - ContractInitResult: 合约初始化与调用结果数据模型

内部方法：
    无

公开接口的 Pydantic 模型：
    - NodeStatus
    - ContractInitResult
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


class ContractInitResult(BaseModel):
    """Counter 合约初始化（拷贝、部署、调用）结果。"""

    counter_sol_exists: bool = Field(description="目标目录下是否存在 Counter.sol")
    copied_counter_sol: bool = Field(description="是否从 assets/ 拷贝了 Counter.sol")
    console_ready: bool = Field(description="控制台是否成功启动并进入交互提示符")
    deploy_success: bool = Field(description="是否执行了 deploy Counter 并认为成功")
    contract_address: str | None = Field(default=None, description="从 getDeployLog 解析到的合约地址")
    link_success: bool = Field(default=False, description="是否已将合约地址链接到 /apps/Counter")
    increment_sent: bool = Field(description="是否已发送 increment 调用")
    errors: list[str] = Field(default_factory=list, description="流程中的错误或警告集合")