from pydantic_settings import BaseSettings


class Config(BaseSettings):
    linux_execution_file_url: str = "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-linux-x86_64.tar.gz"
    macos_execution_file_url: str = "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-macOS-x86_64.tar.gz"
    windows_execution_file_url: str = "windows 目前不支持"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


config = Config()