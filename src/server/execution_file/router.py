from typing import List

from fastapi import APIRouter
from . import services
from .schemas import Platform

router = APIRouter(prefix="/lightnode", tags=["Lightnode"])


@router.get("/executions/{platform}", response_model=str)
async def get_execution_file_url(platform: Platform) -> str:
    """
    获取执行文件的 URL。
    """
    return services.get_execution_file_url(platform)

@router.get("/config", response_model=str)
async def get_lightnode_config() -> str:
    """
    获取 lightnode 配置。
    """
    return services.get_lightnode_config()

@router.get("/genesis", response_model=str)
async def get_lightnode_genesis() -> str:
    """
    获取 lightnode 创世文件。
    """
    return services.get_lightnode_genesis()

@router.get("/nodes", response_model=List[str])
async def get_nodes_config() -> List[str]:
    """
    获取 nodes 配置。
    """
    return services.get_nodes_config()

@router.get("/ezdeploy/{platform}", response_model=str)
async def get_lightnode_ezdeploy(platform: Platform) -> str:
    """
    获取 lightnode 部署文件。
    """
    return services.get_lightnode_ezdeploy(platform)

@router.get("/build_chain.sh", response_model=str)
async def get_build_chain_sh() -> str:
    """
    获取 build_chain.sh 脚本。
    """
    return services.get_build_chain_sh()