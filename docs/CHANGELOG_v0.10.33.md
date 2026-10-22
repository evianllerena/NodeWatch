# NodeWatch v0.10.33 — Start-up hotfix

Build: `2026-10-17-v0.10.33-startup-no-block`. Everything in v0.10.32, plus:

## "NodeWatch backend startup failed before secure verification completed"
- **Cause:** the backend loaded the vendor connectors and started its background services (Mist warm-up, Event
  Relay, alerting, backups, presence) *before* it accepted its first connection. When any of that was slow, the
  launcher's 40-second handshake expired first. Your logs show both v0.10.30 (from 18:41) and v0.10.32 reaching
  "Backend entering uvicorn.run" and then never answering. The code those two versions share was the cause, not a
  v0.10.32 change.
- **Fix:**
  - the server answers immediately and all of that start-up work runs in the background (pages that need the
    connectors wait for them);
  - the handshake answer no longer touches the Mist client, settings or credentials.
- **If a start ever hangs again,** `logs\startup-trace.txt` gets every thread's stack after 25 s, so the cause
  is visible straight away. The application log also times each start-up step ("Background start-up finished
  in … ms").
