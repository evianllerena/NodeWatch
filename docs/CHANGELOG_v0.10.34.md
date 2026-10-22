# NodeWatch v0.10.34 — The real cause of "startup failed before secure verification"

Build: `2026-10-17-v0.10.34-launcher-version`. Everything in v0.10.33, plus the launcher fix.

- **Cause:** the Windows launcher checks the backend's version against its own. In the launchers shipped since
  v0.10.30 that check still expected **0.10.29**: the compiler had built the version into the machine code, and
  only the text copies were updated. Every backend answered the handshake correctly and was rejected, until the
  launcher gave up after 40 s. That is why v0.10.30, v0.10.32 and v0.10.33 all failed and v0.10.29 worked.
- **Fix:** the launcher now expects 0.10.34 everywhere it compares the version (three places). This was checked
  by disassembling the launcher.
- The Mac launcher takes its version from the build settings, not from the code, and was not affected.
