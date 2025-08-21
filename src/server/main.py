"""
FastAPI 应用入口点。
"""

from loguru import logger
from contextlib import asynccontextmanager
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from fastapi import FastAPI
from src.server.ca.router import router as ca_router
from src.server.execution_file.router import router as execution_file_router
from src.server.fisco_v2.router import router as fisco_router

from src.server.config import config

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        # 延迟导入，避免在测试环境无二进制时报错影响导入
        from src.server.fisco_v2.services import ensure_started

        status = ensure_started()
        logger.info(f"FISCO 节点启动状态: {status.model_dump_json(indent=4)}")
        yield
    except Exception as e:
        logger.warning(f"启动时未能确保 FISCO 节点运行：{e}")
        raise e
    finally:
        # 应用关闭事件处理器 - 自动停止 FISCO 节点
        try:
            logger.info("应用关闭，正在停止 FISCO 节点...")
            from src.server.fisco_v2.services.node_process import stop_node
            stop_node()
            logger.info("FISCO 节点已停止")
        except Exception as e:
            logger.error(f"停止 FISCO 节点时发生错误: {e}")

app = FastAPI(title="FISCO BCOS Certificate Authority Service", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 包含证书签发服务的路由
app.include_router(ca_router, prefix="/v1")
app.include_router(execution_file_router, prefix="/v1")
app.include_router(fisco_router, prefix="/v1")

logger.info(f"config: {config.model_dump_json(indent=4)}")


@app.get("/{path}")
async def index(path: str):
    return FileResponse(path="dist/index.html")


app.mount("/", StaticFiles(directory="dist", html=True), name="frontend")
