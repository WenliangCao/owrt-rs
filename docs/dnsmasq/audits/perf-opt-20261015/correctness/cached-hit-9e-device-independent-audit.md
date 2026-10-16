# Exact G/9e original ten-window independent audit

The retained evidence passes independent verification. None of the three primary metrics is discernible under the original frozen rules; this screen supplies neither a performance win nor a regression finding.

Author `06ee1e89`, result SHA256 `ea3ad82e348cc49053acd5f4744aa1405d407bdd4f0a4f1e0d920c7643a9fbe9`. [Complete independent report](cached-hit-9e-device-independent-audit.json), SHA256 `11f2dda717ca2c4a5c6ea0a99db6519e5f2b2853fa34b5d5b1dbe00fd6cca411`.

| Metric | G median | 9e median | Change | W | Same direction | Discernible |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| CPU µs/query | 118 | 114 | -3.3898% | 10.5263% | 3/5 | No |
| p50 ms | 0.17512 | 0.166503 | -4.9206% | 17.1438% | 3/5 | No |
| p95 ms | 0.324927 | 0.311077 | -4.2625% | 44.2742% | 3/5 | No |

All ten alternating windows and full ranges remain. CPU uses 5,000 correct warmup-plus-measurement queries; median CPU ticks differ by 2, below the required strict **>8** threshold. The original `abs(delta)>W`, at least four paired directions and every CPU window ≥10 ticks rules are unchanged. Ties and adverse paired directions are retained.

The audit checked ten safe exact archives containing 430 regular files, all raw latency/send-lag/scheduled-latency data, 313 single-thread observations, 600 existing wire samples, and all three primary plus seven resource comparisons. Exact 9e source179/SDK and actual965/original12+3+3 signal result contents are bound to the independent qualification reports, including case order and shipped Rust binary identity.

The frozen health validator passes 126 baseline samples and all 428 runtime samples with zero tail samples, plus 10 baseline and 30 runtime external checks. All ten window intervals fit the guard. Seventeen original postflight predicates, four-only immutable-copy cleanup, exact E/F restoration and production PID/start `[3086, 2115]` are supported by the captured records.

Original native work overlapped on the separate Oracle host. Its controller launch is distinguished from its first measured command; the last native command end is explicitly derived, not an invented original end field. Owner32 starts after device closure. No Oracle-idle or hardware-isolation claim is made.

The initial local signal binding expected incorrect SIGTERM/INT names. The successful binding uses the unchanged original SIGHUP/SIGUSR2/SIGUSR1/SIGALRM result. Only the author/session explanation of the failed inline assertion is retained; no independent failed-script or stdio bytes exist. No signal, product or measured window was rerun. One reviewer SDK input-location error was corrected to use the complete original downloaded package, with matching staged build identity.

This combined 9e comparison is not an isolated-component estimate and does not complete full44/full110 or authorize deployment. Accepted G remains unchanged. Review was local-only; no router or Oracle access occurred.
