from __future__ import annotations

from fastapi import APIRouter, Response, Request, HTTPException
from fastapi.responses import FileResponse
from fastapi import WebSocket, WebSocketDisconnect
import pexpect
from loguru import logger
from pydantic import BaseModel
from urllib.parse import parse_qs

from .auth import (
    init_secret,
    verify_secret,
    create_session,
    COOKIE_NAME,
    require_session,
    is_valid_session,
)
from .console import console_manager


router = APIRouter(prefix="/panel", tags=["Hidden Panel"]) 


@router.get("")
async def get_panel_index():
    # 直接返回后端自带的终端面板 HTML（独立，绕过前端打包问题）
    return FileResponse(path="src/server/panel/static/panel.html")


class AuthBody(BaseModel):
    secret: str


@router.post("/auth")
async def post_auth(body: AuthBody, response: Response):
    secret = body.secret
    if not verify_secret(secret):
        raise HTTPException(status_code=401, detail="invalid secret")
    session_id = create_session()
    # Create console backend session immediately; no timeout.
    console_manager.open(session_id)
    response.set_cookie(key=COOKIE_NAME, value=session_id, httponly=True, secure=False, samesite="lax", path="/")
    # 同时返回 sid，前端可作为 WebSocket 备选传参（避免某些环境下 Cookie 不随 WS 携带）
    return {"ok": True, "sid": session_id}


class ExecBody(BaseModel):
    command: str


@router.post("/exec")
async def post_exec(request: Request, body: ExecBody):
    session_id = require_session(request)
    output = console_manager.send(session_id, body.command)
    return {"output": output}


@router.websocket("/ws")
async def ws_terminal(websocket: WebSocket):
    # 仅允许已登录会话（从 Cookie 读取）
    await websocket.accept()
    try:
        # WebSocket 在 Starlette 下无法直接读 Cookie? 这里仍可通过 headers 获取
        cookie = websocket.headers.get("cookie", "")
        session_id = None
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE_NAME:
                session_id = v
                break
        # 允许通过查询参数 ?sid=... 作为后备
        if not session_id:
            try:
                q = parse_qs(websocket.url.query or "")
                sid_list = q.get("sid")
                if sid_list:
                    session_id = sid_list[0]
            except Exception:
                session_id = None
        if not session_id or not is_valid_session(session_id):
            await websocket.close(code=4401)
            return

        # 确保后端控制台会话存在
        try:
            console_manager.open(session_id)
        except Exception:
            pass
        child = console_manager.get_child(session_id)

        async def forward_output():
            while child.isalive():
                try:
                    data = await websocket.receive_text()
                    child.send(data)
                except WebSocketDisconnect:
                    break
                except Exception:
                    break

        import asyncio
        async def pump_child():
            while child.isalive():
                try:
                    out = await asyncio.to_thread(child.read_nonblocking, size=1024, timeout=0.1)
                    if out:
                        await websocket.send_text(out)
                except pexpect.exceptions.TIMEOUT:
                    await asyncio.sleep(0.02)
                    continue
                except pexpect.exceptions.EOF:
                    break
                except Exception:
                    break

        import asyncio
        await asyncio.gather(forward_output(), pump_child())
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass
