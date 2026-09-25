# Detection and correlation contract

Signals are defensive observations, not confirmed compromise. Rules operate on
normalized evidence and carry IDs that an analyst can resolve in the timeline.

## Candidate gate

At a successful login, count prior failures with exactly the same user, IP, and
authentication resource. Differences must be strictly positive and no greater
than `window_seconds`. Equal-time failures cannot establish ordering. At least
`failure_threshold` failures produces a 20-point signal.

The success receives a separate 25-point unusual-IP signal only if the user has a
configured baseline and the IP is absent from it. Both signals must refer to the
same success before a candidate exists. No baseline means insufficient information.

## Context and additional risk

The candidate window starts at its earliest supporting failure and ends inclusively
after `window_seconds`. This is a total window, not a fresh window for every event.
Evidence joins on user and IP across resources and sources. A `viewer` → `admin`
application event contributes 30; a cloud-like `DownloadObject` of at least
`large_transfer_bytes` contributes 25. These must occur strictly after the success
and within the total window. No order between escalation and download is required.

All supporting additional signals remain visible, but risk counts each rule once.
No repeated event or replay can inflate the same rule's weight. Another candidate
success already within the same user's/IP's emitted window is suppressed. A later
independent window or another identity can produce another incident.

## Boundaries and tuning

Default values: 20 failures, 600 seconds, 100 MiB. They are teaching defaults with
no production validation. Medium begins at 40 and high at 70. Score is capped at
100. High volume, expected administrator changes, or a poor baseline can cause
false positives. Split source IPs and missing telemetry can cause false negatives.

Failure bursts without a success, standalone privilege changes, and standalone
downloads do not become incidents in this version. Web and firewall events add
context only. The suite tests benign input, boundary values, mismatched identity,
IP and authentication resource, old failures, and out-of-order escalation.

Return to the [README](../README.md).
