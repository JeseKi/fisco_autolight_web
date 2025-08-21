# FISCO BCOS Web 管理平台

本项目是一个基于 React、TypeScript 和 Vite 构建的 Web 应用程序，用于管理和监控 FISCO BCOS 轻节点。

## 功能特性

- 轻节点部署与管理
- 节点状态监控
- 区块链数据查询
- 智能合约交互

## 技术栈

- **前端框架**: React 19
- **语言**: TypeScript
- **构建工具**: Vite
- **包管理器**: pnpm
- **代码检查**: ESLint (with TypeScript ESLint)
- **类型检查**: TypeScript

## 快速开始

### 环境准备

确保您已安装以下工具：

- [Node.js](https://nodejs.org/) (推荐 LTS 版本)
- [pnpm](https://pnpm.io/)

### 安装依赖

```bash
pnpm install
```

### 启动开发服务器

```bash
pnpm dev
```

这将启动一个本地开发服务器，通常在 `http://localhost:5173`。

### 构建生产版本

```bash
pnpm build
```

构建后的文件将输出到 `dist` 目录。

### 预览生产构建

```bash
pnpm preview
```

## 配置

项目使用 `config.json` 文件进行配置。请参考 `config.json.example` 文件创建您的配置文件。

主要配置项包括：

- `linux_execution_file_url`: Linux 平台轻节点执行文件下载地址。
- `macos_execution_file_url`: macOS 平台轻节点执行文件下载地址。
- `linux_lightnode_ezdeploy_url`: Linux 平台轻节点一键部署脚本地址。
- `mac_lightnode_ezdeploy_url`: macOS 平台轻节点一键部署脚本地址。
- `windows_execution_file_url`: Windows 平台支持信息。
- `nodes`: 已配置的节点列表。

### 配置文件详解

配置文件 (`config.json`) 支持从多个来源加载配置，优先级顺序如下：

1. 程序传参 (最高优先级)
2. 环境变量
3. `.env` 文件
4. `config.json` 文件 (最低优先级)

示例配置文件内容：
```json
{
    "linux_execution_file_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-lightnode",
    "macos_execution_file_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-lightnode",
    "linux_lightnode_ezdeploy_url" : "https://github.com/JeseKi/fisco_autolight_client",
    "mac_lightnode_ezdeploy_url" : "https://github.com/JeseKi/fisco_autolight_client",
    "windows_execution_file_url" : "windows 目前不支持",
    "nodes" : []
}
```

配置项说明：
- `linux_execution_file_url`: Linux 平台轻节点执行文件的下载 URL。
- `macos_execution_file_url`: macOS 平台轻节点执行文件的下载 URL。
- `linux_lightnode_ezdeploy_url`: Linux 平台轻节点一键部署脚本的 URL。
- `mac_lightnode_ezdeploy_url`: macOS 平台轻节点一键部署脚本的 URL。
- `windows_execution_file_url`: Windows 平台的支持信息（当前不支持）。
- `nodes`: 初始化的节点列表，可以是字符串数组。

## 部署

本项目支持通过 Docker 进行部署。

### 使用 Docker 部署

1. 构建 Docker 镜像

```bash
docker build -t fisco-web .
```

2. 运行容器

```bash
docker run -d -p 8000:8000 --name fisco-web-container fisco-web
```

### 使用 Docker Compose 部署

项目提供了 `docker-compose.yml` 文件，可以通过以下命令一键部署：

```bash
docker-compose up -d
```

默认会启动一个服务，监听端口 `8000`。

## 代码质量

- 使用 ESLint 进行代码风格检查。
- 使用 TypeScript 进行静态类型检查。

运行代码检查：

```bash
pnpm lint
```

## 项目结构

```
fisco_web/
├── assets/          # 静态资源
├── src/             # 源代码
├── public/          # 公共文件
├── dist/            # 构建输出目录
├── index.html       # 入口 HTML 文件
├── package.json     # 项目配置文件
├── tsconfig.json    # TypeScript 配置
├── vite.config.ts   # Vite 配置
├── eslint.config.js # ESLint 配置
├── config.json.example # 配置文件示例
├── Dockerfile       # Docker 配置文件
└── docker-compose.yml # Docker Compose 配置文件
```

## 贡献

欢迎提交 Issue 和 Pull Request 来改进本项目。

## 许可证

[MIT](LICENSE)