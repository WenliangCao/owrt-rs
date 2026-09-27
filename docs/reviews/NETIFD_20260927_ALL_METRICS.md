# 全部工程结果：描述性汇总

1036观察、26strata、572比较；不代表原矩阵完成或自动验收。百分比为100×[exp(median(log(candidate/baseline)))−1]，CPU/延迟负值较好，吞吐正值较好。每行n是完整三侧block数，不能用请求数替代。

## 核心指标

| Stratum | Baseline | n完整三侧block | 主体own CPU | mean | p50 | p95 | p99 | 吞吐 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| main-32/interface_dump | C | 20 | -33.148% | -16.811% | -18.122% | -11.818% | -1.137% | +11.316% |
| main-32/interface_dump | R89 | 20 | -10.027% | -6.561% | -6.030% | -5.686% | -0.600% | +5.296% |
| main-32/lan_status | C | 20 | -21.582% | -9.659% | -10.790% | -6.687% | -4.540% | +5.313% |
| main-32/lan_status | R89 | 20 | +1.602% | -0.763% | -0.598% | +0.870% | +0.253% | +0.886% |
| main-32/device_status | C | 20 | -42.830% | -33.491% | -34.368% | -31.474% | -28.245% | +40.831% |
| main-32/device_status | R89 | 20 | -38.434% | -30.334% | -30.588% | -28.920% | -26.291% | +35.412% |
| main-32/interface_dump_c4 | C | 20 | -42.074% | -18.762% | -19.652% | -12.757% | -6.985% | +14.212% |
| main-32/interface_dump_c4 | R89 | 20 | -18.310% | -8.764% | -9.845% | -8.489% | -6.963% | +6.887% |
| main-32/lan_status_c4 | C | 20 | -35.389% | -9.498% | -10.388% | -6.911% | -6.688% | +8.697% |
| main-32/lan_status_c4 | R89 | 20 | -13.699% | -3.661% | -4.011% | -5.848% | -5.903% | +3.366% |
| main-32/device_status_c4 | C | 20 | -45.424% | -36.234% | -36.147% | -26.828% | -18.435% | +49.312% |
| main-32/device_status_c4 | R89 | 20 | -40.782% | -30.030% | -29.270% | -21.884% | -15.488% | +37.266% |
| main-32/device_status_all | C | 20 | -55.723% | -45.628% | -46.250% | -42.940% | -38.810% | +64.066% |
| main-32/device_status_all | R89 | 20 | -51.309% | -41.844% | -42.163% | -39.243% | -39.247% | +54.946% |
| main-32/device_status_all_c4 | C | 20 | -59.124% | -50.583% | -51.606% | -35.143% | -28.277% | +84.311% |
| main-32/device_status_all_c4 | R89 | 20 | -54.515% | -45.677% | -46.156% | -32.780% | -32.282% | +68.815% |
| main-32/interface_dump_32 | C | 20 | -56.306% | -39.816% | -42.422% | -30.559% | -25.883% | +18.657% |
| main-32/interface_dump_32 | R89 | 20 | -37.458% | -19.936% | -22.134% | -13.191% | -13.707% | +6.364% |
| main-32/interface_dump_32_c4 | C | 20 | -57.774% | -36.405% | -38.217% | -24.583% | -20.113% | +22.265% |
| main-32/interface_dump_32_c4 | R89 | 20 | -34.924% | -15.241% | -16.253% | -7.980% | -5.108% | +8.836% |
| main-32/interface_named_32 | C | 20 | -24.545% | -8.229% | -11.143% | +0.372% | +0.955% | +7.006% |
| main-32/interface_named_32 | R89 | 20 | +0.330% | +0.574% | -0.040% | +4.496% | +0.657% | -0.461% |
| main-32/interface_named_32_c4 | C | 20 | -31.631% | -6.964% | -8.322% | -2.374% | -1.733% | +7.592% |
| main-32/interface_named_32_c4 | R89 | 20 | -11.398% | -0.530% | -2.072% | +0.516% | -1.922% | +1.298% |
| scale-64/interface_dump_64 | C | 20 | -60.179% | -41.466% | -42.799% | -36.072% | -32.898% | +20.025% |
| scale-64/interface_dump_64 | R89 | 20 | -36.914% | -18.679% | -19.371% | -16.532% | -10.196% | +6.146% |
| scale-64/interface_dump_64_c4 | C | 20 | -59.391% | -39.064% | -41.026% | -27.197% | -25.738% | +24.806% |
| scale-64/interface_dump_64_c4 | R89 | 20 | -35.277% | -14.954% | -17.539% | -6.945% | -7.871% | +7.363% |
| scale-64/interface_named_64 | C | 20 | -30.851% | -11.645% | -12.631% | -7.423% | -3.238% | +10.077% |
| scale-64/interface_named_64 | R89 | 20 | -13.657% | -6.220% | -6.855% | -9.124% | -2.662% | +5.465% |
| scale-64/interface_named_64_c4 | C | 20 | -33.090% | -3.125% | -6.532% | -0.246% | -0.205% | +5.339% |
| scale-64/interface_named_64_c4 | R89 | 20 | -15.246% | -1.676% | -2.568% | -0.320% | -1.475% | +1.614% |
| scale-128-dump/interface_dump_128 | C | 3 | -53.764% | -39.875% | -41.941% | -34.512% | -19.762% | +16.781% |
| scale-128-dump/interface_dump_128 | R89 | 3 | -22.591% | -14.498% | -15.369% | -13.598% | +10.503% | +4.922% |
| scale-128-dump/interface_dump_128_c4 | C | 3 | -53.634% | -41.960% | -44.112% | -34.548% | -35.951% | +22.182% |
| scale-128-dump/interface_dump_128_c4 | R89 | 3 | -24.741% | -12.029% | -14.531% | -7.163% | -9.893% | +6.821% |
| scale-128-named/interface_named_128 | C | 2 | -28.769% | -22.257% | -13.921% | -15.315% | -24.696% | +22.797% |
| scale-128-named/interface_named_128 | R89 | 2 | -19.177% | -11.242% | -11.708% | -8.996% | -2.202% | +11.271% |
| scale-128-named/interface_named_128_c4 | C | 2 | -38.356% | -25.125% | -17.587% | -35.043% | -59.255% | +32.720% |
| scale-128-named/interface_named_128_c4 | R89 | 2 | -21.351% | -3.034% | -3.522% | -0.484% | +0.400% | +2.470% |
| wireless-empty/wireless_status | C | 2 | -95.756% | -86.209% | -85.429% | -90.044% | -89.032% | +617.344% |
| wireless-empty/wireless_status | R89 | 2 | -17.355% | -7.070% | -6.376% | -9.600% | -9.559% | +7.647% |
| wireless-empty/wireless_status_c4 | C | 2 | -96.950% | -88.738% | -88.947% | -87.796% | -88.950% | +734.369% |
| wireless-empty/wireless_status_c4 | R89 | 2 | -28.856% | +0.844% | -0.138% | +5.080% | +9.792% | -3.614% |
| wireless-actual/wireless_status | C | 3 | -93.241% | -75.997% | -76.849% | -70.498% | -61.088% | +158.510% |
| wireless-actual/wireless_status | R89 | 3 | -91.287% | -80.684% | -82.581% | -73.912% | -58.981% | +193.651% |
| wireless-actual/wireless_status_c4 | C | 3 | -94.542% | -81.321% | -81.059% | -73.827% | -76.025% | +286.788% |
| wireless-actual/wireless_status_c4 | R89 | 3 | -92.597% | -74.334% | -73.733% | -64.060% | -62.144% | +186.219% |
| reload-actual-32/reload_unchanged | C | 2 | -63.632% | -62.623% | -63.066% | -59.041% | -55.381% | +167.426% |
| reload-actual-32/reload_unchanged | R89 | 2 | -9.908% | -8.467% | -8.987% | -4.760% | +2.539% | +9.242% |
| events-static2/events_static2 | C | 2 | +50.306% | -50.101% | -50.226% | -45.974% | -45.656% | +100.369% |
| events-static2/events_static2 | R89 | 2 | -9.874% | +0.750% | -0.202% | +10.385% | +17.764% | -0.744% |

- Descriptive evidence only: no CI,1144-family guarantee, equivalence, automatic PASS or component acceptance.
- n20 old main32/scale64, n3 actual wireless and legacy128dump, n2 other new groups stay separate.
- Legacy128dump retains all11 windows; only3 complete three-side blocks are paired. Final2 windows/4 lane observations remain unpaired, never discarded or cross-block paired.
- Over-budget indices cover every pair in complete three-side blocks; incomplete-block observations have no admitted comparison and remain explicit raw rows.
- Own/tree and adverse/over-budget indices overlap; do not add them as independent failures. A favorable median can contain adverse windows.
- Priority is a point-only flag using complete shared blocks; unlike describe ratios it does not require positive lower uncertainty bounds. It cannot repair an unresolved ratio.
- All original counter intervals, c4 denominators, event cycle units, resource04 three FAILs and recovery48/58 drift limits remain.
- RSS/Anon/HWM/fd/thread values are original sampled summaries; unavailable roles/peaks remain unavailable, not zero.

# 角色CPU明细

1036观察、26strata、572比较；不代表原矩阵完成或自动验收。百分比为100×[exp(median(log(candidate/baseline)))−1]，CPU/延迟负值较好，吞吐正值较好。每行n是完整三侧block数，不能用请求数替代。

## 全部角色own/tree CPU

事件场景的 caller own 仅为 benchmark 自身CPU；listen/subscribe observer 的 own/child CPU
在原始资料中单列，并计入 caller tree。两列不是相同的进程范围。

| Stratum | Baseline | n完整三侧block | 主体own | 依赖own | caller own | 主体tree | 依赖tree | caller tree |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| main-32/interface_dump | C | 20 | -33.148% | -4.250% | -2.792% | -33.148% | -4.250% | -2.792% |
| main-32/interface_dump | R89 | 20 | -10.027% | -1.192% | -3.659% | -10.027% | -1.192% | -3.659% |
| main-32/lan_status | C | 20 | -21.582% | +1.311% | +1.752% | -21.582% | +1.311% | +1.752% |
| main-32/lan_status | R89 | 20 | +1.602% | +0.221% | -1.413% | +1.602% | +0.221% | -1.413% |
| main-32/device_status | C | 20 | -42.830% | +1.655% | -3.511% | -42.830% | +1.655% | -3.511% |
| main-32/device_status | R89 | 20 | -38.434% | -6.159% | -2.297% | -38.434% | -6.159% | -2.297% |
| main-32/interface_dump_c4 | C | 20 | -42.074% | -0.110% | -0.895% | -42.074% | -0.110% | -0.895% |
| main-32/interface_dump_c4 | R89 | 20 | -18.310% | -0.970% | -2.281% | -18.310% | -0.970% | -2.281% |
| main-32/lan_status_c4 | C | 20 | -35.389% | -5.803% | -0.185% | -35.389% | -5.803% | -0.185% |
| main-32/lan_status_c4 | R89 | 20 | -13.699% | -0.338% | -3.884% | -13.699% | -0.338% | -3.884% |
| main-32/device_status_c4 | C | 20 | -45.424% | -10.631% | -5.018% | -45.424% | -10.631% | -5.018% |
| main-32/device_status_c4 | R89 | 20 | -40.782% | -12.367% | -4.533% | -40.782% | -12.367% | -4.533% |
| main-32/device_status_all | C | 20 | -55.723% | -1.262% | -2.256% | -55.723% | -1.262% | -2.256% |
| main-32/device_status_all | R89 | 20 | -51.309% | -7.030% | -1.809% | -51.309% | -7.030% | -1.809% |
| main-32/device_status_all_c4 | C | 20 | -59.124% | -15.320% | -6.467% | -59.124% | -15.320% | -6.467% |
| main-32/device_status_all_c4 | R89 | 20 | -54.515% | -16.602% | -5.343% | -54.515% | -16.602% | -5.343% |
| main-32/interface_dump_32 | C | 20 | -56.306% | +0.006% | -0.300% | -56.306% | +0.006% | -0.300% |
| main-32/interface_dump_32 | R89 | 20 | -37.458% | -12.752% | +0.183% | -37.458% | -12.752% | +0.183% |
| main-32/interface_dump_32_c4 | C | 20 | -57.774% | -0.076% | +0.649% | -57.774% | -0.076% | +0.649% |
| main-32/interface_dump_32_c4 | R89 | 20 | -34.924% | -4.174% | -0.676% | -34.924% | -4.174% | -0.676% |
| main-32/interface_named_32 | C | 20 | -24.545% | -1.799% | +0.533% | -24.545% | -1.799% | +0.533% |
| main-32/interface_named_32 | R89 | 20 | +0.330% | +2.040% | +0.914% | +0.330% | +2.040% | +0.914% |
| main-32/interface_named_32_c4 | C | 20 | -31.631% | -2.965% | +0.047% | -31.631% | -2.965% | +0.047% |
| main-32/interface_named_32_c4 | R89 | 20 | -11.398% | +1.200% | -1.495% | -11.398% | +1.200% | -1.495% |
| scale-64/interface_dump_64 | C | 20 | -60.179% | -3.505% | +0.284% | -60.179% | -3.505% | +0.284% |
| scale-64/interface_dump_64 | R89 | 20 | -36.914% | +3.753% | +0.849% | -36.914% | +3.753% | +0.849% |
| scale-64/interface_dump_64_c4 | C | 20 | -59.391% | -1.287% | +1.011% | -59.391% | -1.287% | +1.011% |
| scale-64/interface_dump_64_c4 | R89 | 20 | -35.277% | +0.654% | -0.012% | -35.277% | +0.654% | -0.012% |
| scale-64/interface_named_64 | C | 20 | -30.851% | -4.198% | +1.953% | -30.851% | -4.198% | +1.953% |
| scale-64/interface_named_64 | R89 | 20 | -13.657% | -1.800% | -2.145% | -13.657% | -1.800% | -2.145% |
| scale-64/interface_named_64_c4 | C | 20 | -33.090% | -2.977% | +1.549% | -33.090% | -2.977% | +1.549% |
| scale-64/interface_named_64_c4 | R89 | 20 | -15.246% | -1.183% | -0.832% | -15.246% | -1.183% | -0.832% |
| scale-128-dump/interface_dump_128 | C | 3 | -53.764% | -2.929% | +0.421% | -53.764% | -2.929% | +0.421% |
| scale-128-dump/interface_dump_128 | R89 | 3 | -22.591% | -0.725% | -0.243% | -22.591% | -0.725% | -0.243% |
| scale-128-dump/interface_dump_128_c4 | C | 3 | -53.634% | -0.989% | +0.688% | -53.634% | -0.989% | +0.688% |
| scale-128-dump/interface_dump_128_c4 | R89 | 3 | -24.741% | -0.784% | -0.870% | -24.741% | -0.784% | -0.870% |
| scale-128-named/interface_named_128 | C | 2 | -28.769% | -9.085% | -6.295% | -28.769% | -9.085% | -6.295% |
| scale-128-named/interface_named_128 | R89 | 2 | -19.177% | -4.943% | -6.969% | -19.177% | -4.943% | -6.969% |
| scale-128-named/interface_named_128_c4 | C | 2 | -38.356% | -12.369% | -9.303% | -38.356% | -12.369% | -9.303% |
| scale-128-named/interface_named_128_c4 | R89 | 2 | -21.351% | -5.461% | -4.071% | -21.351% | -5.461% | -4.071% |
| wireless-empty/wireless_status | C | 2 | -95.756% | -41.952% | -61.760% | -95.756% | -41.952% | -61.760% |
| wireless-empty/wireless_status | R89 | 2 | -17.355% | -3.071% | -1.673% | -17.355% | -3.071% | -1.673% |
| wireless-empty/wireless_status_c4 | C | 2 | -96.950% | -46.703% | -54.055% | -96.950% | -46.703% | -54.055% |
| wireless-empty/wireless_status_c4 | R89 | 2 | -28.856% | -1.155% | +2.697% | -28.856% | -1.155% | +2.697% |
| wireless-actual/wireless_status | C | 3 | -93.241% | -46.417% | -28.557% | -93.241% | -46.417% | -28.557% |
| wireless-actual/wireless_status | R89 | 3 | -91.287% | -36.158% | -19.020% | -91.287% | -36.158% | -19.020% |
| wireless-actual/wireless_status_c4 | C | 3 | -94.542% | -33.038% | -24.008% | -94.542% | -33.038% | -24.008% |
| wireless-actual/wireless_status_c4 | R89 | 3 | -92.597% | -34.280% | -13.420% | -92.597% | -34.280% | -13.420% |
| reload-actual-32/reload_unchanged | C | 2 | -63.632% | -71.646% | -10.504% | -63.632% | -71.646% | -10.504% |
| reload-actual-32/reload_unchanged | R89 | 2 | -9.908% | -2.501% | -0.598% | -9.908% | -2.501% | -0.598% |
| events-static2/events_static2 | C | 2 | +50.306% | -1.434% | -0.700% | +1.588% | -1.434% | -0.694% |
| events-static2/events_static2 | R89 | 2 | -9.874% | +0.298% | +0.589% | -0.459% | +0.298% | -0.203% |

- Descriptive evidence only: no CI,1144-family guarantee, equivalence, automatic PASS or component acceptance.
- n20 old main32/scale64, n3 actual wireless and legacy128dump, n2 other new groups stay separate.
- Legacy128dump retains all11 windows; only3 complete three-side blocks are paired. Final2 windows/4 lane observations remain unpaired, never discarded or cross-block paired.
- Over-budget indices cover every pair in complete three-side blocks; incomplete-block observations have no admitted comparison and remain explicit raw rows.
- Own/tree and adverse/over-budget indices overlap; do not add them as independent failures. A favorable median can contain adverse windows.
- Priority is a point-only flag using complete shared blocks; unlike describe ratios it does not require positive lower uncertainty bounds. It cannot repair an unresolved ratio.
- All original counter intervals, c4 denominators, event cycle units, resource04 three FAILs and recovery48/58 drift limits remain.
- RSS/Anon/HWM/fd/thread values are original sampled summaries; unavailable roles/peaks remain unavailable, not zero.
