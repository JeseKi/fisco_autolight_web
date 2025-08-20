"""
FastAPI 应用入口点。
"""

from loguru import logger
from contextlib import asynccontextmanager

from fastapi import FastAPI
from src.server.ca.router import router as ca_router
from src.server.execution_file.router import router as execution_file_router
from src.server.fisco.router import router as fisco_router

from src.server.config import config

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        # 延迟导入，避免在测试环境无二进制时报错影响导入
        from src.server.fisco.services import ensure_started

        status = ensure_started()
        logger.info(f"FISCO 节点启动状态: {status.model_dump_json(indent=4)}")
        yield
    except Exception as e:
        logger.warning(f"启动时未能确保 FISCO 节点运行：{e}")
        raise e

app = FastAPI(title="FISCO BCOS Certificate Authority Service", lifespan=lifespan)

# 包含证书签发服务的路由
app.include_router(ca_router, prefix="/v1")
app.include_router(execution_file_router, prefix="/v1")
app.include_router(fisco_router, prefix="/v1")

logger.info(f"config: {config.model_dump_json(indent=4)}")


@app.get("/")
async def root():
    return {"message": "Welcome to the FISCO BCOS Certificate Authority Service"}