# Security Policy

## Supported Versions

Only the latest release is supported.

## Reporting a Vulnerability

If you believe you have found a vulnerability in Tasia itself (not in the stacks it
scans), report it privately through GitHub:
<https://github.com/joeyvictorino/tasia/security/advisories/new>

Please do not file public issues for suspected security problems in the tool. This is a
personal open-source project; there is no formal response-time commitment.

## What Tasia does and does not claim

Tasia is a local, static analysis tool. Explicitly:

- **Tasia never transmits your files or secret values.** It reads config files on
  your machine and writes a `.tasia/` pack locally. The only optional network call
  is `tasia explain`, which sends **only the findings** to a local Ollama you run
  yourself. Findings never carry secret values by construction (evidence is a key
  name, port, image, or the flagged config token), and a defense-in-depth redactor
  scrubs common token formats before sending.
- **Tasia never scans the internet.** It does not probe hosts, open sockets to your
  services, or reach out to any remote endpoint (other than the local Ollama above).
- **Tasia does not read or print secret values.** It reports secret **key names**
  only, never their values.
- **Tasia does not prove security or compliance.** A clean result means the
  deterministic rules found no matching misconfigurations — not that the deployment
  is secure, audited, or compliant with any standard. Findings are meant to be
  reviewed by a human before action.
- **Tasia never modifies your files.** Hardening suggestions are written to
  `.tasia/` as separate artifacts; your sources are never edited.
