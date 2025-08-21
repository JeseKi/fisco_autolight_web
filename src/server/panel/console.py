from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Dict
from pathlib import Path
import os
import re

import pexpect
from loguru import logger

from src.server.fisco_v2.services.node_setup import _get_code_dir


@dataclass
class ConsoleSession:
    child: pexpect.spawn
    lock: threading.Lock


class ConsoleManager:
    def __init__(self) -> None:
        self._sessions: Dict[str, ConsoleSession] = {}
        self._lock = threading.Lock()

    def _spawn_console(self) -> pexpect.spawn:
        code_dir = _get_code_dir()
        cmd = "stdbuf -i0 -o0 -e0 bash console/start.sh"
        child = pexpect.spawn(
            cmd,
            cwd=str(code_dir),
            encoding="utf-8",
            echo=False,
            timeout=5,
            env={
                **os.environ,
                "TERM": "xterm-256color",
                "COLUMNS": "160",
            },
        )
        return child

    def open(self, session_id: str) -> None:
        with self._lock:
            if session_id in self._sessions:
                return
            child = self._spawn_console()
            # wait for prompt
            try:
                child.expect(r"\[group\d+\]: /apps>", timeout=30)
            except Exception as e:
                try:
                    child.close(force=True)
                except Exception:
                    pass
                raise RuntimeError(f"控制台未就绪: {e}")
            self._sessions[session_id] = ConsoleSession(child=child, lock=threading.Lock())
            logger.info(f"控制台会话已创建: {session_id}")

    def get_child(self, session_id: str) -> pexpect.spawn:
        with self._lock:
            sess = self._sessions.get(session_id)
        if not sess:
            raise RuntimeError("控制台会话不存在")
        return sess.child

    def close(self, session_id: str) -> None:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if sess is not None:
            try:
                if sess.child.isalive():
                    sess.child.sendline("exit")
                    try:
                        sess.child.expect(pexpect.EOF, timeout=3)
                    except Exception:
                        pass
                    sess.child.close(force=True)
            except Exception:
                pass

    def _sanitize(self, text: str) -> str:
        if not text:
            return ""
        # 去除 ANSI ESC 序列 (CSI/OSC 等)
        ansi_re = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\][\s\S]*?\u0007")
        text = ansi_re.sub("", text)
        # 去除非 ESC 开头但残留的 CSI/SGR 片段，如 "[?1000l", "[35m", "[m", "[?1h=" 等
        text = re.sub(r"\[\?[0-9;]+[hl]=?", "", text)  # DEC 私有模式
        text = re.sub(r"\[[0-9;]*m", "", text)         # 颜色 SGR
        return text.strip("\n\r ")

    def send(self, session_id: str, command: str, prompt_timeout: int = 30) -> str:
        with self._lock:
            sess = self._sessions.get(session_id)
        if sess is None:
            raise RuntimeError("控制台会话不存在")

        with sess.lock:
            sess.child.sendline(command)
            try:
                sess.child.expect(r"\[group\d+\]: /apps>", timeout=prompt_timeout)
                raw = sess.child.before or ""
                return self._sanitize(raw)
            except Exception as e:
                logger.warning(f"命令执行失败: {e}")
                return ""


console_manager = ConsoleManager()
