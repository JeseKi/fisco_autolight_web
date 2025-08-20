"""
文件功能：
    FISCO 节点管理的 FastAPI 路由：暴露节点状态查询与手动启动接口。

公开接口：
    - GET /fisco/status -> NodeStatus
    - POST /fisco/ensure-started -> NodeStatus

内部方法：
    无
"""

from __future__ import annotations

from fastapi import APIRouter

from .schemas import NodeStatus
from . import services


router = APIRouter(prefix="/fisco", tags=["FISCO Node"])


@router.get("/status", response_model=NodeStatus)
async def get_status() -> NodeStatus:
    """获取节点状态。"""
    return services.status()


@router.post("/ensure-started", response_model=NodeStatus)
async def post_ensure_started() -> NodeStatus:
    """确保节点已初始化并启动。"""
    return services.ensure_started()


