# 控制台

服务端的控制台不直接暴露在主页上，而是只能通过`/panel`路由进行 Web 访问，当然，您也可以按照[ FISCO 官方教程](https://fisco-bcos-doc.readthedocs.io/zh-cn/latest/docs/quick_start/air_installation.html#id11)的方法来访问控制台，一般来说，控制台在容器中的部署目录在 `/app/src/server/fisco_v2/console` ，通过 `cd /app/src/server/fisco_v2/console` 后直接 `bash start.sh` 即可在容器内直接访问并使用控制台。

继续回到我们的通过 Web 来进行访问展开图，如，我可以通过 `http://localhost:8000` 可以访问到这样的页面：

![success_webpage](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221120739.png)

那我就可以通过 `http://locahost:8000/panel` 来访问到我们的控制台页面：

![console_unauth](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221126126.png)

这时候我们在[快速开始](quick_start.md)中提到的**秘钥**就派上用场了，在这里粘贴或输入我们的秘钥：

![secret_input](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221127222.png)

然后再点击【进入】按钮即可进入到我们的控制台了。

控制台输出【connected】就代表已经连上控制台了。

![console_auth](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221128138.png)

我们键入 `ls`。

![ls_output](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221130252.png)

可以看到我们部署的初始智能合约[`Counter`](../assets/Counter.sol)。

键入 `call Counter get`。

您可以看到这个合约目前被调用 `increment` 方法的次数。

一般来说，因为服务刚部署，因此预期的被调用的次数为 **0** 。

![counter_0](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221132744.png)

键入 `getBlockNumber`，可以看到目前区块链高度。

![record](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221136811.png)

预期数值应当是 **2**。因为我们服务在初始化的时候执行了两次写操作。

1. 部署 Counter 智能合约
2. 将 Counter 智能合约从远程地址链接到本地的 `/app` 下。

对于 `get` 方法，因为是读操作，因此不会被记录到区块链的账本上，也就不会增加区块链高度。

现在我们可以通过键入 `call Counter increment` 来保证我们的智能合约是正常运行的：

![running](https://tuchuang-1317479375.cos.ap-beijing.myqcloud.com/202508221138811.png)

这里我们可以看到 Counter 返回的 `increment` 调用次数为 **1**，区块链高度为 **3**，因为我们的 `increment` 是属于写操作，会被记录在区块链的账本上，会增加区块链的高度。

后续您可以进行通过这个控制台来进行其他区块链操作，如部署智能合约，进行交易等。

具体您可以参考 **[FISCO 官方文档](https://fisco-bcos-doc.readthedocs.io/zh-cn/latest/index.html)**。