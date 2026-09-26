# wazuh-decoders

Wazuh 5.0 (beta) custom decoders for the `ad-domain-controller-detections` integration. Built and validated via Log Test against real production events from a Windows AD environment (DCs, file servers, RDS brokers).

All decoder definitions live in [`decoders/`](decoders/).

## Architecture notes (read first)

- **Custom and Standard spaces run as separate, parallel pipelines.** A decoder in the Custom space **cannot** be parented to a Standard-space decoder (e.g. `decoder/windows-event/0`) — promotion will fail with `Parent '...' does not exist`. Every decoder here is self-contained: it matches directly against `event.original` (the raw XML) rather than relying on fields Standard would normally populate.
- **A root decoder cannot itself have `parents`.** `ad-domain-controller-root/0` exists purely as a parentless entry point so the integration can be promoted; all real decoders chain from it.
- **Promotion path:** Draft → Test → Custom, via SecurityAnalytics → Overview → Actions → Promote. Only Custom-space processing is live on real traffic.

### Engine syntax quirks (this beta build)

- No `stages:` wrapper — `check` / `normalize` are top-level keys.
- `map` entries are a list of single-key `{field: value}` items, not one multi-key dict.
- Map keys are written plain (`event.code:`), not prefixed with `$`. `$` is only used to reference a field as a *value* (e.g. `$event.original`).
- No `parse` stage exists separately — extraction happens inside `normalize` via `regex_extract()`.
- Helper functions cannot be nested (e.g. `parse_long(regex_extract(...))` fails) — extract to a temp `_field` first, then convert in a second map line.
- `regex_extract()` does **not** return an object keyed by named capture groups — call it once per field you need, each with its own single capture group.
- String literals inside helper calls must use **single quotes** for the pattern itself when the value is YAML-double-quoted (needed whenever the pattern contains `:` which YAML would otherwise parse as a new mapping key).
- Backslash escape classes like `\S` are **not** supported inside engine string literals — use a character class like `[^ ]` instead.
- `concat()` requires **2–150 arguments** — pad a single literal with `concat("value", "")`.
- Typed fields (e.g. `event.severity`, `source.port`) reject strings — wrap numeric extractions in `parse_long(...)`, and use bare numbers (not `concat`) for `event.severity`.
- Negation syntax like `!string_equal(...)` does not work (produces a `filter(...)` mismatch, not a negated check). Workaround: set the "default" outcome in the main `map`, then override it in a `check` block for the specific matching case.
- Fields prefixed with `_` (e.g. `_bind_type`) are temporary — stripped automatically by the `cleanup/DecoderTemporaryVariables` step. Never map a value to a `_`-prefixed field expecting it to persist.

### Unverified / worth confirming before relying on them

- `%%1841` as the "Yes" code for `ElevatedToken` on event 4624 — inferred from the code pattern, never confirmed against a real elevated-logon sample.
- All `event.severity` values are placeholder guesses on an improvised 0–100 scale — normalize to your actual ruleset's scale.
- `network.protocol` and `destination.domain` as field choices for auth package / target service are reasonable ECS fits, not officially confirmed mappings.

## Decoders

| File | Decoder name | Event(s) | Purpose |
|---|---|---|---|
| [`ad-domain-controller-root.yml`](decoders/ad-domain-controller-root.yml) | `decoder/ad-domain-controller-root/0` | — | Root placeholder — required as the integration's entry point since a root decoder cannot have `parents`. |
| [`ad-ldap-unsigned-bind.yml`](decoders/ad-ldap-unsigned-bind.yml) | `decoder/ad-ldap-unsigned-bind/0` | 2889 | Unsigned or plaintext LDAP bind to a domain controller. `_bind_type` 1 = plaintext simple bind, 0 = unsigned SASL bind. |
| [`ad-smb1-access.yml`](decoders/ad-smb1-access.yml) | `decoder/ad-smb1-access/0` | 3000 | Legacy SMB1 protocol access attempt (`Microsoft-Windows-SMBServer/Audit`). |
| [`ad-ntlm-auth.yml`](decoders/ad-ntlm-auth.yml) | `decoder/ad-ntlm-auth/0` | 8004 | NTLM authentication audit, client-side (`Microsoft-Windows-NTLM/Operational`). `destination.domain` (from `SChannelName`) is the actual target server being authenticated to. |
| [`ad-powershell-script-logging.yml`](decoders/ad-powershell-script-logging.yml) | `decoder/ad-powershell-script-logging/0` | 4103/4104 | Command invocation context and full script block text (`Microsoft-Windows-PowerShell/Operational`). `message` on 4103 captures the raw `Payload` (parameter bindings), useful for spotting things like credential/connection-string reads. |
| [`ad-kerberos-service-ticket.yml`](decoders/ad-kerberos-service-ticket.yml) | `decoder/ad-kerberos-service-ticket/0` | 4769 | Kerberos service ticket (TGS) request. `destination.domain` (`ServiceName`) is the actual resource being accessed — the field that's missing from 4625 failed-logon events. |
| [`ad-logon-success.yml`](decoders/ad-logon-success.yml) | `decoder/ad-logon-success/0` | 4624 | Successful logon. `event.reason` carries the raw `LogonType` code (e.g. `logon_type_3` = network logon) for later lookup. |

**Note:** `source.address` on the Kerberos and logon-success decoders will be in IPv4-mapped IPv6 form (e.g. `::ffff:10.2.30.216`) — not stripped, since further parsing risked another round of engine quirks. Strip `::ffff:` at query time if needed.

## Not decoded (checked and skipped)

- **Event 4634** (logoff) — fully covered by Standard's `windows-security/0`; remaining raw fields (`LogonType`, `TargetLogonId`) add little value for a logoff on their own.
- **Event 132** (`Microsoft-Windows-WinRM/Operational`, `operationName: EventDelivery`) — internal WinRM plumbing, no user/source/account data. Recommended to exclude at the `<query>` filter level in `agent.conf` rather than decode.
- **Event 4776** (NTLM server-side validation) — Standard already covers everything except the client `Workstation` field, which duplicates what 8004 already provides from the client side; only worth adding if 8004 coverage is incomplete somewhere.

## Pending / discussed but not yet built

- A **rule** on `ad-ldap-unsigned-bind` output (`event.action` = `ldap_plaintext_bind` / `ldap_unsigned_bind`) plus a **Detector** to actually generate Findings/alerts — decoders only enrich events, they don't alert.
- SMB signing (event 3021/3027) and channel binding — audit GPOs enabled but could not be triggered synthetically (modern clients, including Samba, always advertise the signing capability even when configured not to use it); relies on real legacy devices surfacing naturally.
- Cross-referencing 4625 (failed logon) with network/firewall logs (FortiGate) for true destination-host correlation, since DC-side 4625 has no destination field of its own.
