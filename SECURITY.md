# Security policy

AegisLens is a defensive tool, so its own security matters. Thank you for helping keep it safe.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
(Security tab > "Report a vulnerability") and include:

- what is affected (module, class, configuration) and the version or commit;
- steps to reproduce, ideally with a small synthetic input file (never real malware or someone else's data);
- what you expected and what happened.

You can expect a first answer within 7 days. Fixes are released as a patch version and credited to you unless you
prefer otherwise.

## In scope

- Code execution, file reads or network requests triggered by analysed input (log lines, files, URLs, XML exports).
- Bypassing the SSRF guard of the page fetch, the size limits, or the XML external-entity protection.
- SQL injection, or reading the database through the SQL console beyond its read-only, single-SELECT rules.
- API keys or tokens leaking into logs, the database, error messages or AI prompts.
- The container sandbox escaping its limits (no network, read-only sample, dropped capabilities, resource limits).

## Out of scope

- Detection gaps or false alarms: open a normal issue with a synthetic example instead.
- Problems that need an already compromised machine or administrator access to the data folder.
- Running the container sandbox outside a disposable VM, against the documented advice.

## What AegisLens never does

- It never executes, loads or imports the files and logs it analyses. Only the `sandbox` package may start processes,
  and the local sandbox runs only the project's own demo programs.
- It never changes a firewall: it writes block lists and commands for a person to review.
- It never sends raw log lines to cloud AI; addresses and user names are replaced first, and keys come only from
  environment variables.
