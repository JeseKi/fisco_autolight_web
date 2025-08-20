"""
配置加载模块：支持 .env、环境变量、工作目录 config.json（或 CONFIG_FILE 指定）多来源合并。
公开接口：
- Config: 读取配置的设置类
- config: Config 的单例实例
内部方法：
- Config.settings_customise_sources: 自定义配置来源顺序
- Config.parse_nodes: 将字符串/JSON 解析为 List[str]
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict, PydanticBaseSettingsSource


class Config(BaseSettings):
    linux_execution_file_url: str = "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-linux-x86_64.tar.gz"
    macos_execution_file_url: str = "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-macOS-x86_64.tar.gz"
    windows_execution_file_url: str = "windows 目前不支持"
    fisco_url: str = "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos"
    linux_lightnode_ezdeploy_url: str = "https://github.com/JeseKi/fisco_autolight_client"
    mac_lightnode_ezdeploy_url: str = "https://github.com/JeseKi/fisco_autolight_client"
    nodes: List[str] = []

    # pydantic v2 风格配置（等价于旧版的 class Config）
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("nodes", mode="before")
    @classmethod
    def parse_nodes(cls, value: Any) -> List[str]:
        """支持从环境变量以 JSON 或分隔符（逗号/分号/空白）解析 nodes。"""
        if value is None or value == "":
            return []
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str):
            text = value.strip()
            # 优先尝试 JSON
            try:
                loaded = json.loads(text)
                if isinstance(loaded, list):
                    return [str(v) for v in loaded]
            except Exception:
                pass
            # 回退为分隔符拆分（, ; 空白）
            parts = [p for p in re.split(r"[\s,;]+", text) if p]
            return parts
        return value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        """自定义配置来源顺序：入参 > 环境变量 > .env > config.json > secrets。"""

        class JsonFileSettingsSource(PydanticBaseSettingsSource):
            """从工作目录的 config.json（或 CONFIG_FILE 指定路径）加载配置的自定义 Source。"""

            def __init__(self, settings_cls):
                super().__init__(settings_cls)
                self._data: Dict[str, Any] | None = None

            def _load(self) -> None:
                if self._data is not None:
                    return
                cfg_path = os.environ.get("CONFIG_FILE")
                path = Path(cfg_path) if cfg_path else Path.cwd() / "config.json"
                if not path.exists():
                    self._data = {}
                    return
                try:
                    with path.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._data = data if isinstance(data, dict) else {}
                except Exception:
                    self._data = {}

            def __call__(self) -> Dict[str, Any]:
                self._load()
                return dict(self._data or {})

            def get_field_value(self, field):  # type: ignore[override]
                """为满足抽象基类要求，按键名/别名返回字段值。"""
                self._load()
                data = self._data or {}
                key_alias = getattr(field, "alias", None) or getattr(field, "name", None)
                if isinstance(data, dict):
                    if key_alias in data:
                        return data[key_alias], key_alias, True
                    # 再尝试原始字段名
                    key_name = getattr(field, "name", None)
                    if key_name in data:
                        return data[key_name], key_name, True
                return None, None, False

        return (
            init_settings,
            env_settings,
            dotenv_settings,
            JsonFileSettingsSource(settings_cls),
            file_secret_settings,
        )


config = Config()