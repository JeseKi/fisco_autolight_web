from __future__ import annotations

import os
from pathlib import Path
import secrets
import threading
from typing import Optional

from fastapi import HTTPException, Request, status
from loguru import logger


_SECRET_FILE_NAME = "secret.key"
_PANEL_SECRET: Optional[str] = None
_SESSIONS: set[str] = set()
_LOCK = threading.Lock()


def _get_secret_file_path() -> Path:
    return Path.cwd() / _SECRET_FILE_NAME


def load_or_create_secret() -> str:
    """Load panel secret from Path.cwd()/secret.key; create if missing.

    Returns the secret string.
    """
    path = _get_secret_file_path()
    if path.exists():
        try:
            secret = path.read_text(encoding="utf-8").strip()
            if not secret:
                raise ValueError("secret file is empty")
            return secret
        except Exception as e:
            logger.warning(f"读取面板密钥失败，将重新生成: {e}")
    # create new secret
    secret = secrets.token_urlsafe(48)
    try:
        path.write_text(secret + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except Exception as e:
        logger.warning(f"写入面板密钥文件失败: {e}")
    logger.warning(f"Panel secret generated. Keep it safe: {secret}")
    return secret


def init_secret() -> None:
    global _PANEL_SECRET
    with _LOCK:
        if _PANEL_SECRET is None:
            _PANEL_SECRET = load_or_create_secret()


def get_secret() -> str:
    global _PANEL_SECRET
    if _PANEL_SECRET is None:
        init_secret()
    assert _PANEL_SECRET is not None
    return _PANEL_SECRET


def verify_secret(input_secret: str) -> bool:
    try:
        expected = get_secret()
        # constant-time compare
        return secrets.compare_digest(expected, (input_secret or ""))
    except Exception:
        return False


def create_session() -> str:
    session_id = secrets.token_urlsafe(48)
    with _LOCK:
        _SESSIONS.add(session_id)
    return session_id


def revoke_session(session_id: str) -> None:
    with _LOCK:
        _SESSIONS.discard(session_id)


def is_valid_session(session_id: Optional[str]) -> bool:
    if not session_id:
        return False
    with _LOCK:
        return session_id in _SESSIONS


COOKIE_NAME = "panel_session"


def get_session_cookie_from_request(request: Request) -> Optional[str]:
    return request.cookies.get(COOKIE_NAME)


def require_session(request: Request) -> str:
    session_id = get_session_cookie_from_request(request)
    if not is_valid_session(session_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    assert session_id is not None
    return session_id
