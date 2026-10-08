# A 内部余额：已冻结的配置上限并发补门

2026-10-08续接。目标产品仍独立A `69bccf2738f2c07cbc6d8b8a950015d4cea10af3`，
SHA `21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b`。
本工具提交不改产品、诊断模板或现有原语/服务/CPU矩阵；未访问Oracle。

[已冻结设计5.6](../M6B_TCP_MEMORY_DESIGN.md#5-实施步骤与验收门)明确要求20和配置上限并发，
每次记录live requested、块/分片/历史版本和排空余额，循环至少10批。
[fresh门](M6B_TCP_A_FRESH_GATES.md)进一步要求记录20/上限view。
public `capacity-20-30`只记录G、FD和产品PSS，不能证明配置上限的view/root内部余额。
因此新增仅一个 `limit30` profile，固定capacity150及 `max-tcp-connections=30`，
不把它与0/1/4096/16384容量做交叉矩阵。

## 保全与边界

续接时已有未提交草稿先保全到
`E/M6B/resume-20261008/worktree-patches/m6b-a-interleaved-pressure-limit30.{patch,json}`，
patch SHA `e1a9edcb1891cc231cd25cd4d218aeb24df6bc44d2d4aa5d432d7e64a54ee4b7`，11,803 B。
E为ignored `private/dnsmasq-rewrite/evidence`。随后才补collector和pure controls。

沿用原固定名字/600s单A回答和structural warm＋10批，不增加新名字集合。
每批实际accept30独立view、父替换、每child成功force-refresh后命中；保持至少2.2s，
要求两条相隔至少0.9s的真实1Hz trace都有 `clients=G=dns_work=views=30` 及old/private根。
31st原请求在满30时等待；父UDP和已有TCP继续回答；释放一条后同一31st请求回答。
collector核对实际config文件、warm/全部10批的完整且有序观察、原UBus gauge收据、
排队/恢复query字节同一性和原始回复。排空、初末live/object/root/capacity严格余额及
0/1/5/15/60s真实间隔与原门相同。实际raw另做缺view和缩短hold两项负控。

## 本地检查与实际执行

pure Python13/13 controls通过，原始stdout/stderr、工具字节和argv/SHA在
`E/M6B/resume-20261008/limit30-tool-controls-02`；首轮13/13也完整保留于`-01`。
新增controls拒绝丢slot/view、缺warm/批、短hold/trace间隔、单行充双行、错capacity/config、
遗漏/重复/重排progress与recovery、假满gauge、不同的恢复请求；原capacity1七controls仍过。
这些均为synthetic证据校验器测试，没有daemon、namespace、socket或Rust执行，
不授实际资源、产品PSS或CPU资格。

root整合工具并fresh freeze后，用绑定同69bc的新companion/实际六方法controls串行执行：

```sh
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_internal.py" run \
  --image-root "$M6B_IMAGE" --rust "$M6B_DIAG_ELF" --bound-receipt "$M6B_BOUND" \
  --profile limit30 --capacity 150 --out "$M6B_LIMIT30_OUT" </dev/null
python3 "$M6B_TOOLS/m6b_tcp_internal.py" collect --run "$M6B_LIMIT30_OUT" \
  --controls "$M6B_ACTUAL_CONTROLS" --out "$M6B_LIMIT30_RESULT" </dev/null
```

全部output须fresh ignored路径；不覆盖旧门。仅此profile内部余额通过不能代表其它压力门；
诊断额外FD/1Hz采样/System计数仍不能用于产品PSS或CPU。public11与最终完整回归独立执行。
