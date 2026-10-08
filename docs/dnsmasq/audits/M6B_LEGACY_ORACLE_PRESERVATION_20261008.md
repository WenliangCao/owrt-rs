# M6b 旧 Oracle 七 root 完整保全

2026-10-08实际完成；当前pair-signal-01不在选择范围，物理路由器未操作。
此前只见局部保全的EDNS/interface/logging失败、targeted、后增answer/reverse以及全部
source/tests/ELF/maps均补入各旧root的完整snapshot，不把子目录归档扩大成父目录资格。

| 旧 root | 路径数 | 完整 tar SHA256 |
| --- | ---: | --- |
| a-fresh-d8ddb22b | 21596 | 00ef33d7b27d5bd5ae374f1527c073bbb054baf5a75130dea5b2548da01edf66 |
| pair-reverse-fixed-01 | 3422 | 117d894a46fc2cb11b3cc977489461bf9e14667e2099af309bce4129eb5e3265 |
| pair-reverse-fixed-02 | 51797 | d5d45ddcbc4088b59bab43f3ce6fccd87039db58e7546149862d48caa1f2ffc3 |
| pair-neighbor-tail-01 | 6343 | 01b5fc8453fb2664a144ebe94400f176b48605d17f4c333b96364c4a12df0b0d |
| pair-neighbor-tail-02 | 6385 | 09d53335975990eb21bfb7311dd1443e1129fbf9e50bdee86979330916d15346 |
| pair-service-fixes-01 | 7525 | 073991d7c34735aa770680e67830b24f4d9dea862a2f6827567d1044bf385607 |
| pair-udp-acl-01 | 14850 | 7552277cd7b0b25e76a57cb634ced00cb8988aee9450bc857fb9dc5803b74eb1 |

共111918路径。先原完整inventory→cp -a/reflink snapshot→原前/后/副本SHA、type/mode/
uid/gid、纳秒mtime、symlink、device/whiteout/xattrs与hardlink拓扑全等，再完整pack。
本机逐条完整metadata/SHA及hardlink验证过后上传真实proof，只prune staging snapshot；
原root/原C基线仍保留，不能以本次结果声称原root已退役。

全raw/argv/退出/manifest/前后inventory/verification/prune收据在
E/M6B/full-archives/legacy-seven-roots-01（E为ignored证据目录）。completion.all_roots_completed=true、
original_roots_pruned=false，completion SHA
`2b7a714bdb241b6e3f668cebdbe37cb1f04328b5626f7e115d0db8fdc2969fba`。
静态入口资产在E/M6B/resume-20261008/legacy-archive-plan；实际代号01，不覆盖旧保全。
本次保全不把任何旧失败翻通过，也不授A79e服务/资源/CPU资格。
