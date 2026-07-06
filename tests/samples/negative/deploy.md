# Deploy runbook (benign goodware sample)

To deploy the web service:

1. Run `git pull` on the app server.
2. Install dependencies with `pip install -r requirements.txt`.
3. Restart the service: `systemctl restart acme-web`.
4. Verify health at `https://internal.example.com/healthz`.

This document mentions PowerShell and web requests only in passing prose and
contains no encoded commands, cradles, or webshell sinks.
