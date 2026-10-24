# NodeWatch protection verification (Phase 3)

Every release is checked, on the real published download, by the **protection** workflow
(`.github/workflows/protection.yml`, which runs `tools/protection_check.py`). It runs automatically after each
release and on demand, and writes a one-page report (the `protection-report` artifact).

## What is verified

1. **No readable source ships.** Only `app/launcher.py` is Python source; everything else under `app/` is one
   compiled extension module (`app.cp312-win_amd64.pyd` / `app.cpython-312-darwin.so`). The check collects comments
   and docstrings from the source and confirms none of them appear in the compiled module — comments never survive
   compilation and docstrings are stripped (`--python-flag=no_docstrings`).
2. **Integrity is pinned.** `integrity.json` lists every shipped file's SHA-256, and the launcher binary contains
   that manifest's hash.
3. **Anti-tamper works.** The workflow changes one byte of a listed file (`core.js`) and starts the launcher; a
   sound install refuses to start the backend. (The launcher checks every listed file against the manifest and
   quarantines unlisted files — see `docs/SECURITY_MODEL.md`.)
4. **No debug files.** No `.pdb`, `.map`, `__pycache__`, `docs/` or `README` ship (also enforced by the bundle test
   `tests/test_integrity.py`).

## The private unprotected build

For post-mortem debugging of a shipped build, each release run keeps the compiled modules as the private workflow
artifacts `compiled-Windows` and `compiled-macOS` (GitHub Actions artifacts, visible only to the repository). They
are built without packing. The full source at the release's commit is tagged in this private repository. Together
these are the "unprotected internal build" the hardening brief asks to keep privately; nothing unprotected is
published to the release page.

## Anti-lift and decompile resistance

- **A lifted-out module refuses to run.** When NodeWatch ships, the whole app is one compiled extension module
  beside the install's `integrity.json`. If that single file is copied into another program, it is no longer
  beside a manifest that lists it, and importing it raises an error (`app/__init__.py`, `_verify_not_lifted`). The
  guard is fail-open — it refuses only a provable lift and allows on any doubt — so it can never stop a genuine
  start; the launcher's full-manifest check remains the primary integrity gate.
- **Decompile resistance, with evidence kept.** The protection workflow records that the compiled module is native
  code (its first bytes are the PE header, not a `.pyc` magic) and that a standard bytecode decompiler
  (`decompyle3`) rejects it, saving the transcript as the `decompile-evidence` artifact.

## Left to the pentest

An adversarial decompile-and-LLM read of a compiled module — a human expert attempting, with current tooling, to
recover meaningful source and judging what leaks — is part of the runtime penetration test. The mechanical
evidence above (native extension, bytecode decompilers do not apply, no source strings or comments present) is the
input to that review.
