# 快速开始

## 项目模块
概括一下本应用中各个模块的功能如下：

```
.
├── docs # 文档
├── assets # 资产文件
├── config.json # 配置文件，仓库被 clone 下来的时候没有，通常通过 `cp config.json.example config.json` 来进行生成
├── config.json.example # 配置示例文件
├── docker-compose.yml # Docker 部署文件
├── Dockerfile
├── eslint.config.js
├── index.html
├── package.json
├── pnpm-lock.yaml
├── public
├── README.md # README
├── requirements.in # Python 依赖源文件
├── requirements.txt #  Pyhton 依赖文件
├── secret.key # 秘钥文件，仓库刚被 clone 下来的时候没有，但是在启动后会自动生成，用于访问 `/panel` 路由下的控制台
├── solidity # 智能合约文件存放处，放在这里的智能合约会被自动转移到控制台的智能合约目录下，用于部署智能合约
├── src # 源码
├── tsconfig.app.json
├── tsconfig.json
├── tsconfig.node.json
└── vite.config.ts
```

## 配置文件

在部署前，我们需要先生成配置文件：
```bash
cp config.json.example config.json
```

生成后的配置文件如下：
```json
{
    "linux_execution_file_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-lightnode", # 配置 Linux 的 FISCO 可执行文件的路径，一般来说不用改，这个配置等待后续废弃
    "macos_execution_file_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-lightnode", # 同上
    "linux_lightnode_ezdeploy_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/release.linux.zip", # 配置 Linux 的用于轻节点客户端部署的软件包路径
    "mac_lightnode_ezdeploy_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/release.linux.zip", # 同上
    "windows_execution_file_url" : "windows 目前不支持", # FISCO 目前还不原生支持 Windows，后续再说
    "nodes" : [] # 初始连接的节点列表，一般认为是用于部署当前服务的机器 IP:P2PPort，推荐使用公网 IP，不能使用域名
}
```

一般来说，**只需要修改 nodes 这个配置项就可以了，填写部署机器的公网 IP:30300 或 内网IP:30300**。
在本地测试的时候，可以填写`localhost:30300`或`127.0.0.1:30300`

如：
```json
{
    "linux_execution_file_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-lightnode",
    "macos_execution_file_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/fisco-bcos-lightnode",
    "linux_lightnode_ezdeploy_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/release.linux.zip",
    "mac_lightnode_ezdeploy_url" : "https://present-files-1317479375.cos.ap-guangzhou.myqcloud.com/release.linux.zip",
    "windows_execution_file_url" : "windows 目前不支持",
    "nodes" : ["localhost:30300"]
}
```

## Docker 部署

在完成了配置文件的编写后，既可以进行部署了。

我们这里推荐使用 **[Docker](https://www.docker.com/)** 进行部署。

在项目根目录下以 root 身份运行 `docker-compose up -d`即可。

在容器构建并启动后，还没有部署完成，还需要一段时间的初始化，如下：

![](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221109878.png)

在这过程中，**请确保您的网络通畅**。

在执行的过程中，**您可能会遇到因为网络问题导致的失败，这时候请尝试删掉容器并重新部署镜像并启动。**

值得注意的是，在部署过程中，可能会出现注意的日志：

![secret](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221117806.png)

**`safe` 后面是后续会用到的，用于访问面板的秘钥，请您妥善保存。**

查看容器的日志，出现这样的日志：

![success_log](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221113363.png)

访问部署机器的 8000 端口，您可以看到这样的页面：

![success_webpage](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221120739.png)

**就代表部署成功了。**

接下来您可以去查看服务端的[控制台使用方法](console.md)。