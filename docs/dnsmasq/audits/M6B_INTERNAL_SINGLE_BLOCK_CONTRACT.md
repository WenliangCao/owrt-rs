# 内部容量1：真正的 content owner 合同

当前目标为 A `69bccf2738f2c07cbc6d8b8a950015d4cea10af3`。
仅修工具，不改产品，不访问Oracle或构建；容量1仍保留实跑。

`Cache::new(1)`仅有一个content block。每批先accept20独立view，父替换，
再对每个child执行成功force-refresh。每个child都会detach它的唯一旧块；
20个child都完成后，原parent历史块可以合法不再有任何owner。
`m6b_finish_root_sample`统计当前parent/view的唯一根，不把已销毁历史根保留在registry。
所以一律要求`old_pinned_content>0`不是此固定capacity1工作负载的正确结束合同。

新门同时用于实际active等待、warm与十批collector：

- `clients=G=dns_work=views=20`。
- capacity1必须`old_pinned_content=0`、`private_content=20`、`content_versions=21`。
  后两项对应20个独立child私有根和当前parent唯一根，不能以“有任意私有块”放过丢view或额外历史根。
- capacity0必须content/old/private都0；其它容量仍要求真实old+private churn。
- 每批和最终client/view/txn/old/private归零、live requested扣observer后与warm基线相同，
  对象、registry、全部容量/版本余额、10批顺序及0/1/5/15/60真实间隔严格不变。

新增pure Python控制实际7/7通过：容量1正控；少一个private owner、多一个content根、
warm不符；17种client/view/txn/root/live/object/registry异常；缺批／缩短60s；
collector自身全部12个证据负控；容量0及多块门不放宽。
完整轻量执行收据在`E/M6B/resource-capacity1-tool-01/{run.json,stdout,stderr}`，
其中E是ignored `private/dnsmasq-rewrite/evidence`。这些测试只执行Python收据校验器，
没有daemon、namespace、socket或Rust执行，不能当实际资源资格。

root必须在新的resource工具freeze上用同69bcc companion实际运行capacity1，
再由same-source六方法controls与完整raw/collector授资格。旧d8/ae1资源证据只历史。
