"""
定期将新增的 Solidity 合约文件转移到 FISCO 控制台目录中。

行为:
- 监视一个源目录 (默认: project_root/"solidity")。
- 每隔 `interval_seconds` 秒扫描一次 `*.sol` 文件，并将其移动到
  `<code_dir>/console/contracts/solidity` 目录 (必要时会自动创建目录)。
- 如果目标文件已存在且内容相同，则删除源文件。
- 如果内容不同，则以原子方式覆盖目标文件，然后删除源文件。

此模块特意使用简单的周期性轮询实现，以避免
外部依赖 (例如 watchdog)。它从 FastAPI 生命周期中启动。
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path
from typing import Optional

from loguru import logger

from .node_setup import _get_code_dir


def _get_source_dir() -> Path:
    """解析用于监视新 Solidity 文件的目录。

    优先级:
    1) 环境变量 `SOL_CONTRACTS_SRC_DIR` (绝对路径或相对于当前工作目录的路径)
    2) 默认为 `<project_root>/solidity`
    """
    env_path = os.getenv("SOL_CONTRACTS_SRC_DIR")
    if env_path:
        p = Path(env_path)
        return p if p.is_absolute() else (Path.cwd() / p)
    return Path.cwd() / "solidity"


def _get_target_dir() -> Path:
    """控制台 Solidity 合约的目标目录。"""
    code_dir = _get_code_dir()
    return code_dir / "console" / "contracts" / "solidity"


def _files_identical(path_a: Path, path_b: Path) -> bool:
    try:
        return path_a.read_bytes() == path_b.read_bytes()
    except Exception:
        return False


async def _periodic_transfer_loop(interval_seconds: float, stop_event: asyncio.Event) -> None:
    source_dir = _get_source_dir()
    target_dir = _get_target_dir()

    # 确保目录存在
    try:
        source_dir.mkdir(parents=True, exist_ok=True)
        target_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.warning(f"初始化合约目录失败: {e}")

    logger.info(
        f"Solidity 合约自动转移任务已启动：source={source_dir} -> target={target_dir}, interval={interval_seconds}s"
    )

    try:
        while not stop_event.is_set():
            try:
                for src in list(source_dir.glob("*.sol")):
                    if not src.is_file():
                        continue
                    dst = target_dir / src.name

                    try:
                        # 如果文件已存在且内容相同，则仅删除源文件
                        if dst.exists() and _files_identical(src, dst):
                            src.unlink(missing_ok=True)
                            logger.info(f"已检测到相同合约，清理源文件：{src.name}")
                            continue

                        # 通过使用临时文件然后替换来原子性地写入
                        temp_dst = dst.with_suffix(dst.suffix + ".tmp")
                        temp_dst.write_bytes(src.read_bytes())
                        try:
                            temp_dst.replace(dst)
                        finally:
                            # 如果出现问题，尽力清理
                            if temp_dst.exists():
                                temp_dst.unlink(missing_ok=True)

                        # 写入成功后删除源文件
                        src.unlink(missing_ok=True)
                        logger.info(f"已转移合约：{src.name} -> {dst}")
                    except Exception as e:
                        logger.warning(f"转移合约失败：{src} -> {dst}，错误：{e}")
            except Exception as loop_err:
                logger.warning(f"合约目录扫描异常：{loop_err}")

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
            except asyncio.TimeoutError:
                # 定期唤醒
                pass
    finally:
        logger.info("Solidity 合约自动转移任务已停止")


def start_periodic_contract_transfer_task(
    *, interval_seconds: float = 1.0, app: Optional[object] = None
) -> asyncio.Task:
    """启动后台任务，定期移动新增的 Solidity 文件。

    如果提供了 `app` (FastAPI 实例)，创建的任务和停止事件
    将附加到 `app.state` 以进行协调关闭。
    """
    stop_event: asyncio.Event = asyncio.Event()
    task = asyncio.create_task(_periodic_transfer_loop(interval_seconds, stop_event))

    if app is not None:
        try:
            # 附加到 app.state 以进行生命周期管理
            state = getattr(app, "state", None)
            if state is not None:
                setattr(state, "contract_transfer_stop_event", stop_event)
                setattr(state, "contract_transfer_task", task)
        except Exception:
            # 如果状态不可用，则不致命
            pass

    return task


async def stop_periodic_contract_transfer_task(app: Optional[object] = None) -> None:
    """发出信号并等待后台传输任务（如果有）正常停止。"""
    stop_event: asyncio.Event | None = None
    task: asyncio.Task | None = None

    if app is not None:
        try:
            state = getattr(app, "state", None)
            stop_event = getattr(state, "contract_transfer_stop_event", None)
            task = getattr(state, "contract_transfer_task", None)
        except Exception:
            stop_event = None
            task = None

    if stop_event is not None:
        stop_event.set()

    if task is not None:
        try:
            await asyncio.wait_for(task, timeout=5)
        except Exception:
            task.cancel()
            with contextlib.suppress(Exception):
                await task
