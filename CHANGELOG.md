# Changelog

All notable changes to AegisLens are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-09

First public release.

### Added
- **Intrusion detection** for SSH and web-server logs (live tailing, syslog over UDP/TCP, replay): brute force with
  escalation, password spraying, path scans, odd-hour logins, request-rate anomalies, SQL injection, attack-tool user
  agents and threat-list addresses (NET-001 to NET-007, WEB-002).
- **Windows host detection** from Sysmon exports (HOST-001 to HOST-009): suspicious PowerShell, misused Windows tools,
  documents or browsers starting shells, programs in user folders, connections and DNS lookups to listed or look-alike
  destinations, and autostart persistence; optional watched folder for scheduled exports.
- **Windows Security events** (4624, 4625, 4740) from `wevtutil` exports.
- **Static file analysis** (MAL-001 to MAL-006): hashes, entropy, PE/ELF parsing, risky imports, dropper techniques in
  scripts, known-bad hashes, optional VirusTotal lookup, quarantine and a watched download folder.
- **Link checks** (WEB-001 to WEB-005): look-alike domains, injection patterns, threat-list domains, and a consented page
  fetch through an SSRF guard for security headers and suspicious HTML.
- **Sandbox** for the project's own demo programs, and an opt-in container sandbox for a disposable VM.
- **AI explanations** with Claude, Gemini, a local model or offline templates; redaction, budgets and caching.
- **SQLite storage** with views, triggers, FTS5 search, reports with query plans, a read-only SQL console,
  CSV/JSON/HTML export, block-list files, backups and retention.
- **Threat intelligence feeds** (Spamhaus DROP, abuse.ch Feodo) plus your own indicators and feeds.
- **Desktop app** with live-updating screens, a notice for new CRITICAL findings, dark/light/high-contrast designs,
  customisation and an AWT analyst console; **headless mode** with a systemd unit and a Windows logon task.

### Security
- Analysed input is never executed; XML parsing refuses DOCTYPE and external entities; SSRF guard pins the checked
  address; keys only from environment variables; PreparedStatement only.

### Dependencies
- sqlite-jdbc 3.54.1.0 and jackson-databind 2.23.0.

[1.0.0]: https://github.com/sriman676/AegisLens
