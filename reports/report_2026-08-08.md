# T-Pot Honeypot Report - 2026-08-08T21:39:27Z

Source data: `20260808T213920Z` &nbsp;|&nbsp; Total events analyzed: **7604** &nbsp;|&nbsp; Unique attacker IPs: **172**

Events by source: `honeypots`: 508, `suricata`: 6536, `p0f`: 560

_5514 event(s) from allowlisted IPs (`analysis.ignore_ips` in config.yaml) excluded from the metrics below._

## Top Attacking IPs
| IP | Events | Country | City | Org/ASN |
|---|---:|---|---|---|
| `110.35.80.116` | 99 | Indonesia | Tangerang |  |
| `117.177.102.79` | 99 | China | Guangzhou | China Mobile |
| `209.99.185.239` | 93 | Switzerland | Zurich | HostRoyale Technologies |
| `62.210.142.163` | 37 | France | Paris | ONLINE |
| `167.94.146.52` | 14 | Germany | Frankfurt am Main | Censys, Inc. |
| `66.132.224.93` | 13 | United States | Ann Arbor | Censys Inc |
| `195.178.110.217` | 13 | Andorra | Andorra la Vella | Techoff SRV Limited |
| `36.94.136.43` | 12 | Indonesia | Bogor | Telekomunikasi Indonesia |
| `93.174.93.12` | 10 | The Netherlands | Amsterdam | IP Volume inc |
| `71.6.158.166` | 10 | United States | San Diego | CariNet, Inc. |
| `168.76.20.229` | 9 | South Africa | Bloemfontein | Free State Education Department |
| `5.61.209.43` | 9 | The Netherlands | Amsterdam |  |
| `34.124.179.140` | 8 | Singapore | Singapore | Google Cloud (asia-southeast1) |
| `54.87.19.168` | 8 | United States | Ashburn | AWS EC2 (us-east-1) |
| `160.119.76.64` | 7 | The Netherlands | Amsterdam | HostUS Solutions LLC |
| `118.193.37.50` | 6 | Hong Kong | Hong Kong | Ucloud Information Technology (hk) Limited |
| `8.216.13.61` | 6 | Japan | Tokyo | Alibaba.com Singapore E-Commerce Private Limited |
| `195.182.16.23` | 6 | Germany | Frankfurt am Main | Amarutu Technology Ltd |
| `118.26.111.94` | 6 | Singapore | Singapore | Ucloud Information Technology (hk) Limited |
| `31.220.72.85` | 5 | France | Lauterbourg | Contabo GmbH |

## Top Countries
| Country | Events |
|---|---:|
| United States | 163 |
| Indonesia | 113 |
| China | 106 |
| Switzerland | 93 |
| The Netherlands | 60 |
| France | 53 |
| Germany | 44 |
| United Kingdom | 32 |
| Singapore | 17 |
| Andorra | 15 |
| Hong Kong | 9 |
| South Africa | 9 |
| Brazil | 9 |
| Japan | 7 |
| Lithuania | 5 |
| Russia | 4 |
| India | 3 |
| Bulgaria | 2 |
| Iran | 2 |
| Armenia | 2 |

## Top Targeted Ports
| Port | Events |
|---|---:|
| 80 | 401 |
| 443 | 242 |
| 22 | 98 |
| 34332 | 8 |
| 64295 | 3 |
| 60392 | 2 |
| 59506 | 2 |
| 60380 | 1 |
| 50746 | 1 |
| 59498 | 1 |
| 58710 | 1 |

## Attack Patterns
**Likely brute-force sources** (>= 5 auth attempts): 0

**Likely port-scan sources** (>= 5 distinct ports touched): 0

## Malware Families Detected
_Detected via Suricata alert signature matching - see docs/METHODOLOGY.md for caveats._

_None detected in this period._

## Top Credential Pairs Attempted
| Username | Password | Attempts |
|---|---|---:|
| `root` | `000000` | 1 |
| `root` | `111111` | 1 |
| `root` | `123` | 1 |

## Timeline (daily)
| Date | Events |
|---|---:|
| 2026-07-18 | 609 |
| 2026-08-08 | 151 |

---
_Generated automatically by `scripts/analyze_logs.py`. See `scripts/generate_dashboard.py` for a chart-based HTML view of this same data._