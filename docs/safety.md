# Safety and local workflow boundaries

This is a defensive, synthetic educational lab. The runtime has no network clients,
subprocess actions, cloud SDKs, account-management integrations, or live response.
`simulate_account_isolation` only appends a JSON audit record. It cannot isolate an
actual account. Tests launch local Python subprocesses solely to exercise the CLI.

Only documentation IPv4 ranges are accepted in input telemetry and IP baselines:
192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24. All JSON telemetry must be marked
synthetic. These markers are not proof of data provenance. Do not supply secrets,
personal information, production logs, or real infrastructure identifiers.

The app does not load `.env`; no credentials are needed. Git ignores `.env`,
`.env.*` (except an optional `.env.example`), reports, virtual environments, and
lock files. Ignoring files is not secret detection. Inspect staged changes before
committing and use synthetic analyst labels in audit records.

## Approval and persistence

The CLI requires an explicit decision, analyst label, and reason before a simulation
can execute. This is a local teaching state machine, not an authenticated control.
A person with filesystem access can alter reports, approve them under another
label, or rewrite history. Audit records are not signed or tamper-evident.

Report operations use a cooperating `.lock` file and atomic file replacement to
avoid partial writes and concurrent CLI updates. New runs refuse to overwrite a
report. If a killed process leaves `report.json.lock`, first confirm no SOC command
is still using that report, then remove only that stale lock and retry. Do not
place reports in an untrusted shared directory or edit a report during a command.

Parser errors identify source, file, and line without printing the raw record.
Unknown metadata is dropped, but that is not a general-purpose redaction system.
Keep all input synthetic. Reports should remain local and should be reviewed
before they are shared.

Return to the [README](../README.md).
