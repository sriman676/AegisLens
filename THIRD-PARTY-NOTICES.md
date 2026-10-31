# Third-party notices

AegisLens itself is released under the MIT License (see `LICENSE`). Third-party parts keep their own licences, listed
here. Library licences were read on 2026-10-31 from each library's Maven pom (`<licenses>`) or the licence file inside
its JAR.

## Libraries in the runnable JAR
| Library | Version | Licence | Notes |
|---|---|---|---|
| OpenJFX (`javafx-controls`, `-graphics`, `-base`) | 26.0.2 | GPL v2 with Classpath Exception | The Classpath Exception allows shipping it with an application under another licence. The fat JAR includes the native libraries for the OS it was built on. |
| sqlite-jdbc (Xerial) | 3.54.1.0 | Apache License 2.0 | The JAR also carries `LICENSE.zentus` (original Zentus code, BSD-style). The SQLite engine inside is in the public domain. |
| jackson-databind, jackson-core, jackson-annotations | 2.23.0 | Apache License 2.0 | |
| slf4j-api | 2.0.20 | MIT | Only the API (no binding): its "no providers" warning at start-up is expected. |

## Build and test only (not shipped)
| Tool | Version | Licence |
|---|---|---|
| JUnit Jupiter | 6.1.3 | Eclipse Public License 2.0 |
| JaCoCo | 0.8.16 | Eclipse Public License 2.0 |
| Maven plugins (compiler 3.16.0, surefire 3.6.1, shade 3.6.2), javafx-maven-plugin 0.0.8 | | Apache License 2.0 |
| JDK 26 and jpackage | 26.0.2 | GPL v2 with Classpath Exception (OpenJDK) |

## Data and services
| Source | Terms AegisLens follows |
|---|---|
| Spamhaus DROP | Free to use; credit "The Spamhaus Project" (shown in Threat intel); downloaded at most once a day. |
| abuse.ch Feodo Tracker (recommended list) | CC0; best effort, no liability; no aggressive lists; downloaded daily. |
| VirusTotal public API (optional, your own key) | Personal/non-commercial use only; only SHA-256 hashes are sent; 4 lookups per minute, 500 per day. |
| Claude / Gemini APIs (optional, your own keys) | The provider's terms; IP addresses and user names are replaced before sending. |
| `src/main/resources/rules/top-domains.txt` | A list of public domain names compiled for this project (facts, no third-party list copied). |

## Own artwork
The AegisLens logo (`docs/logo.svg`, `src/main/resources/icons/*.png`) and the sidebar icons
(SVG paths in `ui.Icons`) were drawn for this project; no icon set was copied.

## Sample data
Everything in `sample-data/` is synthetic and uses only reserved documentation addresses (192.0.2.x, 198.51.100.x,
203.0.113.x, RFC 5737) and `.test`/`.example` names (RFC 2606). No real logs, no real malware.
