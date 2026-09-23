# R136 Oracle 批量预实验

这一目录只负责 Oracle 构建和筛选；不接触路由器。候选只是 manifest 中的路径和 SHA-256，增加 sendmmsg 或其他候选无需修改 runner。生产结论仍须由选中的**同一个 ELF**在物理路由器确认。

1. 各候选先放入独立、不可变的 `components/` 快照。构建表格式见 `build_batch.py` 的模块说明。`output` 必须为新目录内的 `ubusd-rs`，`work_root` 必须在 `/tmp/owrt-build/r135/` 下且不存在。这里复用原有 R135 SDK 构建脚本，不改变 flags。
2. 构建结束再开始计时，二者不同时跑。构建并发由 `--jobs` 控制，每个 Cargo 本身只有一个编译 worker。先用 2；有更多空闲 CPU 时可增加构建并发。
3. 筛选 manifest 包含所有候选的最终 ELF 身份、固定 benchmark 身份、C 的加载器和动态库身份。输出目录必须是新目录。示例命令：

```sh
python3 tools/r136/build_batch.py /home/ubuntu/r136/build-plan.json --jobs 2 --output /home/ubuntu/r136/build-results.json
sudo python3 tools/r136/oracle_batch.py /home/ubuntu/r136/screen-manifest.json --output /home/ubuntu/r136/screen-01 --pairs 1:0,3:2 --repeats 4 --iterations 10000
python3 tools/r136/analyze_batch.py /home/ubuntu/r136/screen-01 --output /home/ubuntu/r136/screen-results.json
```

`--pairs` 写作 `daemon:caller`。默认两个互不重叠的 CPU 对并行；每对内部候选顺序在块间反转。每个候选/块新建一个 daemon，运行 `register_1`、`register_16`、`event_1`、`event_8`、`event_nomatch`，各有 caller 独占一核和 caller 可用本对两核两种条件。每条 10,000 个周期，20 次预热；5 × 2 × 4 × 2 = 每个候选 80 个原始样本文件。正式运行前可用 `--repeats 1 --iterations 100` 做身份/清理烟测；烟测不可混进筛选结果。

最小筛选表结构（下面是结构示例，不能将省略号当作身份）：

```json
{
  "schema": 1,
  "benchmark": {"path": "/home/ubuntu/r135/benchmark-01/owrt-benchmark", "sha256": "85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d"},
  "rootfs": {
    "loader": "/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/lib/libc.so",
    "library_path": "/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/lib:/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/usr/lib"
  },
  "libraries": {"/absolute/path/to/exact/lib/libc.so": "..."},
  "subjects": [
    {"label": "c", "kind": "c", "path": "/absolute/path/to/exact/sbin/ubusd", "sha256": "cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88"},
    {"label": "r134", "kind": "rust", "path": "/home/ubuntu/r134/out/verify-01/ubusd-rs", "sha256": "98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0"},
    {"label": "sendmmsg-a", "kind": "rust", "path": "/absolute/path/to/new/ubusd-rs", "sha256": "..."}
  ]
}
```

`libraries` 要列出匹配 C 镜像的 libc、libubox、libgcc_s、libblobmsg_json、libjson-c；其路径都必须在实际 C daemon 的 maps 中出现。推荐沿用 `tools/r135/oracle_screen.py` 的 `ROOTFS`、`LIBRARIES` 常量生成该表，禁止猜测 hash。

每次开始时锁定身份，记录实际 argv、maps、PID/starttime、亲和性、clock、上下文切换和原始延迟向量。每次退出都结束本工具创建的进程组、回收 caller/daemon 并删除 socket；异常产生 `FAILED`，不得纳入成功筛选。它不杀其他任务、不调 governor、不改 sysctl。

输出比较保留同 CPU 对、同块、同亲和性、同负载的配对变化，CPU 对不池化。所有正负变化都保留。±1% 仅列为未分辨；Oracle 排名只用于缩小候选范围，不是显著性检验或路由器结论。多个 worker 仍共享主机资源；应避免其他构建/性能任务同时运行。

提交前静态检查与 fake-builder 生命周期检查通过；未在本任务中启动 Oracle 重负载或路由器测试。
