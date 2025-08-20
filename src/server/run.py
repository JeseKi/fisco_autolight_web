#!/usr/bin/env python
import uvicorn
import os
from dotenv import load_dotenv
from pathlib import Path

from loguru import logger

if __name__ == "__main__":
    logger.info("Aetrix CA Service, start running!")
    load_dotenv(Path.cwd() / ".env")
    logger.info(f"当前应用环境：{os.getenv('APP_ENV')}")
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    uvicorn.run(
        "src.server.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="debug",
    )