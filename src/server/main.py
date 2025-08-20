"""
FastAPI 应用入口点。
"""

from fastapi import FastAPI
from src.server.ca.router import router as ca_router
from src.server.execution_file.router import router as execution_file_router

app = FastAPI(title="FISCO BCOS Certificate Authority Service")

# 包含证书签发服务的路由
app.include_router(ca_router, prefix="/v1")
app.include_router(execution_file_router, prefix="/v1")


@app.get("/")
async def root():
    return {"message": "Welcome to the FISCO BCOS Certificate Authority Service"}