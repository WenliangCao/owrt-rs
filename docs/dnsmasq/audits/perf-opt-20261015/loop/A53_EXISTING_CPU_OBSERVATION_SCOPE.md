# Existing A53 CPU evidence: observed scope

The retained G/E full110, exact C/G ten, G/bare1df ten and E-stage50 evidence does **not** record dynamic CPU frequency, governor, daemon affinity masks, migration history, per-process CPU-clock observations or hardware instructions/cycles. A53 IPC attribution remains unavailable; Oracle IPC is a separate scope.

`clock_ticks_per_second=100` comes from `_SC_CLK_TCK`: CPU-time accounting units per second, **not MHz/GHz or processor cycles**. `CLOCK_MONOTONIC` supplies elapsed time. Guard `cpu_policy="record_only"` describes aggregate CPU utilization recording, not a governor.

The full `final.stat` files retain one last-processor value per non-lifecycle window. G/1df's ten endpoints are CPU0 ×2 and CPU1 ×8; they are separate daemon instances sampled after load. A final value is neither an affinity mask nor a migration trace. All140 retained endpoints across the four corpora match their original manifests and PID/start identities, and show nice10; the launcher sets priority, not affinity.

The earlier idle read found no `cpufreq/policy*` directory. That capability observation, static cpuinfo, and a vDSO mapping cannot prove fixed/equal frequency or measured clock-call costs. Frequency and scheduler explanations remain unquantified.

Only existing local evidence was read. No collection, trace, test, threshold or framework was added. User/system endpoint decomposition is left to the separate root-derived report.

[Evidence scope and receipt hash](A53_EXISTING_CPU_OBSERVATION_SCOPE.json)
