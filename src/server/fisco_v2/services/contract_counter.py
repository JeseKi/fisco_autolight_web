"""
文件功能：
    通过控制台完成 Counter 合约的初始化（拷贝、部署、调用 increment）。

公开接口：
    - is_counter_initialized() -> bool
      判断 `console/contracts/solidity/Counter.sol` 是否存在，用于确定合约部署初始化是否已执行。

    - ensure_counter_deployed_and_increment(timeout_s: int = 60) -> ContractInitResult
      确保 Counter.sol 拷贝到控制台目录，执行控制台交互：deploy Counter、getDeployLog 解析地址，并调用 increment。

    - extract_contract_address_from_deploy_log(log_text: str) -> str | None
      从 getDeployLog 的输出文本中解析 Counter 合约地址（公开为纯函数，便于测试）。

内部方法：
    - _get_console_contracts_solidity_dir() -> Path
    - _copy_counter_sol_if_missing() -> tuple[bool, bool]
    - _spawn_console() -> pexpect.spawn
    - _wait_for_prompt(child, timeout_s: int) -> bool
    - _send_and_collect(child, cmd: str, prompt_timeout: int) -> str

公开接口的 Pydantic 模型：
    - ContractInitResult（定义于 `src/server/fisco_v2/schemas.py`）
"""

from __future__ import annotations

import re
from pathlib import Path

import pexpect
from loguru import logger

from ..schemas import ContractInitResult
from .node_setup import _get_code_dir


def _get_console_contracts_solidity_dir() -> Path:
    """获取控制台的 solidity 合约目录。"""
    code_dir = _get_code_dir()
    return code_dir / "console" / "contracts" / "solidity"


def is_counter_initialized() -> bool:
    """判断 Counter.sol 是否已存在于控制台合约目录。"""
    target = _get_console_contracts_solidity_dir() / "Counter.sol"
    return target.exists()


def _copy_counter_sol_if_missing() -> tuple[bool, bool]:
    """若控制台合约目录中不存在 Counter.sol，则从仓库 assets 拷贝。

    返回 (counter_sol_exists, copied)
    """
    target_dir = _get_console_contracts_solidity_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "Counter.sol"

    if target.exists():
        return True, False

    project_root = Path.cwd()
    source = project_root / "assets" / "Counter.sol"
    if not source.exists():
        logger.warning(f"未找到源合约文件: {source}")
        return False, False

    content = source.read_text(encoding="utf-8")
    target.write_text(content, encoding="utf-8")
    logger.info(f"已拷贝 Counter.sol 到控制台目录: {target}")
    return True, True


def _spawn_console() -> pexpect.spawn:
    """启动 FISCO 控制台交互进程。"""
    code_dir = _get_code_dir()
    cmd = "stdbuf -i0 -o0 -e0 bash console/start.sh"
    child = pexpect.spawn(
        cmd,
        cwd=str(code_dir),
        encoding="utf-8",
        echo=False,
        timeout=5,
    )
    return child


def _wait_for_prompt(child: pexpect.spawn, timeout_s: int = 30) -> bool:
    """等待控制台提示符出现。"""
    try:
        # 典型提示符形如：[group0]: /apps>
        child.expect(r"\[group\d+\]: /apps>", timeout=timeout_s)
        return True
    except Exception as e:
        logger.warning(f"等待控制台提示符超时或失败：{e}")
        return False


def _send_and_collect(child: pexpect.spawn, cmd: str, prompt_timeout: int = 30) -> str:
    """发送命令并收集到下一次提示符出现前的所有输出。"""
    child.sendline(cmd)
    try:
        child.expect(r"\[group\d+\]: /apps>", timeout=prompt_timeout)
        # child.before 包含此次命令的输出（不含提示符本身）
        return child.before or ""
    except Exception as e:
        logger.warning(f"命令执行等待提示符失败：{cmd}，错误：{e}")
        return ""


def extract_contract_address_from_deploy_log(log_text: str) -> str | None:
    """从 getDeployLog 输出中提取 Counter 合约地址。

    尝试多种常见格式：
    - 行内包含 Counter 以及 0x 开头的 40 位十六进制地址
    - 或者独立的 address: 0x...，并在邻近上下文出现 Counter
    """
    if not log_text:
        return None

    # 优先匹配带 Counter 的同一行
    for line in log_text.splitlines():
        if "Counter" in line:
            m = re.search(r"0x[a-fA-F0-9]{40}", line)
            if m:
                return m.group(0)

    # 回退：全局找 address: 0x... 的形式
    m2 = re.search(r"address\s*[:=]\s*(0x[a-fA-F0-9]{40})", log_text)
    if m2:
        return m2.group(1)

    # 最后尝试：全局第一个 0x... 地址
    m3 = re.search(r"0x[a-fA-F0-9]{40}", log_text)
    if m3:
        return m3.group(0)

    return None


def ensure_counter_deployed_and_increment(timeout_s: int = 60) -> ContractInitResult:
    """确保 Counter 合约已部署，并执行 increment 调用。"""
    errors: list[str] = []

    exists, copied = _copy_counter_sol_if_missing()

    child: pexpect.spawn | None = None
    console_ready = False
    deploy_success = False
    address: str | None = None
    increment_sent = False

    try:
        child = _spawn_console()
        console_ready = _wait_for_prompt(child, timeout_s=min(30, timeout_s))
        if not console_ready:
            errors.append("控制台未就绪或超时")
            return ContractInitResult(
                counter_sol_exists=exists,
                copied_counter_sol=copied,
                console_ready=False,
                deploy_success=False,
                contract_address=None,
                increment_sent=False,
                errors=errors,
            )

        # 先尝试获取现有部署记录
        log_out = _send_and_collect(child, "getDeployLog", prompt_timeout=30)
        address = extract_contract_address_from_deploy_log(log_out)

        # 如未找到，则尝试部署
        if not address:
            out = _send_and_collect(child, "deploy Counter", prompt_timeout=timeout_s)
            # 部署完成后再次获取日志
            log_out = _send_and_collect(child, "getDeployLog", prompt_timeout=30)
            address = extract_contract_address_from_deploy_log(log_out)
            deploy_success = address is not None
        else:
            deploy_success = True

        if not address:
            errors.append("无法从 getDeployLog 解析 Counter 合约地址")
            return ContractInitResult(
                counter_sol_exists=exists,
                copied_counter_sol=copied,
                console_ready=console_ready,
                deploy_success=deploy_success,
                contract_address=None,
                increment_sent=False,
                errors=errors,
            )

        # 调用 increment
        call_cmd = f"call Counter {address} increment"
        _ = _send_and_collect(child, call_cmd, prompt_timeout=timeout_s)
        increment_sent = True

        return ContractInitResult(
            counter_sol_exists=exists,
            copied_counter_sol=copied,
            console_ready=console_ready,
            deploy_success=deploy_success,
            contract_address=address,
            increment_sent=increment_sent,
            errors=errors,
        )

    except Exception as e:
        logger.warning(f"合约初始化流程发生异常：{e}")
        errors.append(str(e))
        return ContractInitResult(
            counter_sol_exists=exists,
            copied_counter_sol=copied,
            console_ready=console_ready,
            deploy_success=deploy_success,
            contract_address=address,
            increment_sent=increment_sent,
            errors=errors,
        )
    finally:
        try:
            if child is not None and child.isalive():
                child.sendline("exit")
                try:
                    child.expect(pexpect.EOF, timeout=3)
                except Exception:
                    pass
                child.close(force=True)
        except Exception:
            pass


