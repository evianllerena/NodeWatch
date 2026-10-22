# Team triage — shared acknowledge / snooze / dismiss / mute / notes / assign (v0.10.18)

NodeWatch runs one backend per engineer's PC; there is no central server. Up to v0.10.17 the
Command Center's triage state (acknowledged, snoozed, dismissed, muted) lived in a JSON file on each
PC, and only "Acknowledge in Mist" was visible to the rest of the team. Team triage makes that state
shareable — first through a Windows file share, later through a NodeWatch team server — without
changing any tool that uses it.

## The picture

```
 Command Center (attention_service)            records in / records out — unchanged API
        │  load() / update(fn) / housekeep(fn) / record(...)
        ▼
 TriageStoreFacade (triage/store.py)           record changes → events; per-PC overlay for bookkeeping
        │  append(event) · events_since(cursor) · current_state() · health() · describe()
        ▼
 Triage store plug-in (triage/backends/<id>.py, chosen in Settings › Team triage)
   local            this PC only (default)         state/attention_state.events/*.jsonl
   shared_folder    \\server\share\NodeWatch\triage  logs/<machine>~<user>.NNNN.jsonl (one per user+PC)
   nodewatch_server planned, refuses                 HTTP + per-user token (design in the module)
        │
        ▼
 Fold (triage/fold.py) — last-writer-wins per alert, deterministic        Sinks (triage/sinks/)
                                                                           on_event() for events made
                                                                           on this PC (Jira, ServiceNow,
                                                                           Teams, Slack … none ship yet)
```

## Events

Every action is one append-only event (`triage/events.py`):

| Field | Meaning | Bounds |
|---|---|---|
| `id` | uuid4 hex — dedupe key | 8–64 `[A-Za-z0-9-]` |
| `ts` | epoch seconds (hybrid clock, below) | finite, > 0, ≤ now + 300 s |
| `seq` | per-writer counter (tie-break) | int ≥ 0 |
| `actor` | `{user, display, machine}` — Windows user name, optional display name from Settings, computer name | 64 / 80 / 64 chars |
| `action` | `ack unack snooze unsnooze dismiss restore mute unmute note assign unassign` | enum |
| `target_kind`, `target`, `targets` | `alert` (stable alert key), `incident` (notes only) or `mute` (rule id); `targets` repeats the action on up to 2,000 more alert keys | `[A-Za-z0-9:_.-]{1,128}` |
| `fields` | `until`, `until_change`, `duration`, `reason`, `note`, `assignee`, `via`, mute rule fields (`type`, `label`, `source`, `site_key`, `site_name`), `migrated`, `copied` | each typed and length-capped; unknown fields rejected on write, dropped on read |
| `context` | `title`, `type`, `source`, `site_name`, `device_name` of the alert (for history/export) | ≤ 200 chars |
| `source_vendor`, `version` | connector id; schema version (1) | |

Events never contain credentials. A note is limited to 500 characters in the UI (1,000 in the schema).

### Fold rules (deterministic)

* Each alert key has a **state register** (ack / snooze / dismiss set it; unack / unsnooze / restore clear
  it), an **assignee register** (assign / unassign), and each mute rule has a register (mute / unmute).
* An event wins a register when its order `(ts, user, machine, seq, id)` is greater than the current
  winner's. The order is total, so every PC folds any set of events to the same state, whatever order
  the files were read in. Duplicates (same `id`) are ignored; two *different* events with the same id
  resolve the same way on every PC (copies whose actor does not match their file are dropped first,
  then the smaller content hash wins). Notes are an append-only set.
* **Reader-clock independence**: validation never depends on the reader's clock except for the
  future-skew rule below, and a deferred event is accepted unchanged once the clock passes it, so all
  PCs end up accepting the same events (bounds such as `until` are checked against the event's own `ts`).
* **Clock skew**: events stamped more than 5 minutes in the future are rejected when written and
  deferred when read (they count once the reader's clock catches up). Since v0.10.22, events more than
  1 hour ahead are refused outright, so nobody can plant an action that wins later ("time bomb"). New events use a hybrid clock:
  `ts = max(now, newest event already seen for these alerts + 1 ms)`, so acting on what you just saw
  always wins even if your clock is behind a teammate's.
* **Undo** is a compensating event (`restore` after `dismiss`, a `snooze` that re-asserts the previous
  snooze …) — history is never edited. Undo only touches alerts where your action is still the latest
  word; if a teammate acted since, their action stands (the API reports `kept_teammate_changes`).
* **Per-PC housekeeping is not shared**: "last seen" bookkeeping, forgetting records of alerts that
  vanished (24 h while the source answered), expired snoozes / mutes and "until it changes" snoozes
  whose alert changed are decided by each PC and stored in `attention_state.local.json`, keyed by the
  order of the deciding event (a newer action by anyone shows again).

## Stores

### `local` — Only this PC (default)
Event log in `state/attention_state.events/`; `state/attention_state.json` is rewritten as a snapshot
in the old shape (`"format": 2`) so older versions can still read it.

**Migration**: on the first start of v0.10.18 every record of the old `attention_state.json` becomes
one event with the record's own time and fields (authored by the current Windows user, flagged
`migrated`), each mute rule becomes a `mute` event, and the per-PC "last seen" times and the
v0.10.12 legacy flag move to the overlay. The original file is kept as
`attention_state.v1-backup.json`. Migration runs once (never again once the log has events).

### `shared_folder` — Shared folder (preview)
* Path: an absolute UNC path (`\\fileserver\NodeWatch\triage`) or drive path (`S:\NodeWatch\triage`).
  Relative paths, `.`/`..`, device paths (`\\?\`, `\\.\`), URLs, wildcards and control characters are
  rejected. The share root is never created by NodeWatch (a missing share means *offline*).
* Each NodeWatch appends **only to its own file** `logs/<machine>~<user>.NNNN.jsonl` (one complete line
  per write, flush + `fsync`), starting a new segment after 2 MB (500 segments max per writer). Files
  are never renamed or rewritten, so there is no locking and no SMB contention. `~` never occurs in a
  sanitized user or machine name, so the split is unambiguous. Pre-release `<machine>-<user>` files are
  no longer read (v0.10.22): no current client writes them, so anyone could create one under a
  teammate's name.
* The writer remembers its segment number on this PC (`state/triage-shared-<hash>/segment.json`) and
  only moves forward one *full* segment at a time. Before v0.10.22 a teammate could pre-create the
  *next* segment (`alice's .0002`): Alice's appends then failed and his lines in that file counted as
  hers. Now a writer skips any segment file another account created, and readers skip it too (owner
  check below). Readers ignore segment numbers above 500.
* Reader caps: 5,000 files, 500 writers (most recently active first, at most 8 machines per user name —
  v0.10.22; before, the first 500 by name, so 500 junk files could hide every teammate), 32 MB and
  200,000 lines per sync (the rest is read on the next sync), 1,000 waiting future events per writer
  (extra ones are re-read from their file later, never dropped). Everything ignored is reported in
  Settings › Team triage › Sync status (`ignored_files`, `ignored_writers`, `ignored_segments`,
  `foreign_files`, `unverified_files`, `backlog`, `future_events`).
* Everyone reads every log incrementally (byte offset per file), reads complete lines only, skips
  lines over 64 KB or not valid JSON, reads at most 8 MB of any one file, and ignores an event whose
  `actor` does not match the file it is in (no writing as someone else into your own file).
* **Offline**: if the share is unreachable, events go to `state/triage-shared-<hash>/outbox.jsonl`,
  are shown at once, and are written on the next sync (every dashboard refresh, at most every 3 s,
  or *Sync now*). Settings shows *Waiting to sync N*.
* **Read-only**: if the user may read but not write the folder, NodeWatch shows the team's triage and
  refuses new actions with HTTP 403 and a clear message (ask for Modify permission or use *Only this PC*).
* **Trust**: identity is not authentication. Every entry is shown as *Display (user@computer)*; a
  display name also used by another user is flagged; an acknowledgement's "in Mist" is shown as fact
  only for this PC's own entries (NodeWatch made and audited that call) and as *says "in Mist"* for
  anyone else's. An entry whose actor does not match the file it is in is ignored.
  **Owner check (v0.10.22)**: a log file is read only when its Windows *owner* (the account that
  created it) is the user its name claims; otherwise it is skipped and counted as `foreign_files`.
  Changing a file's owner to someone else needs administrator rights, so creating
  `hq-pc~alice.0001.jsonl` no longer lets anyone act as Alice. The local user name comes from the
  signed-in account, not the `%USERNAME%` variable, and display names are compared by look-alike
  skeleton (Cyrillic/Greek look-alikes, accents and zero-width characters no longer slip past).
  **Before v0.10.22 this document said the ACL below made each engineer's entries trustworthy. It did
  not**: the ACL stops people changing others' files, but a forger only had to *create* new ones.
  **On a Mac (v0.10.22)** the owner check is off (`owner_check: not_applicable`): a Mac sees every file on
  an SMB share as owned by the account that mounted it, so owners prove nothing there. Mac users' own
  files are still owned by their share account, so Windows teammates keep checking them — as long as
  the Mac user name matches the share account name. Settings › Team triage shows the state.
  NodeWatch first creates a probe file on the share and reads its owner back: the check is enforced
  only when the owner is the PC's own account (`owner_check: enforced`). Shares that map every user to
  one account (a NAS "force user" setting), Samba unix SIDs or unresolvable owners switch it off for
  that share (`owner_check: unavailable`, shown as *Identity checks: OFF*) instead of hiding everyone.
  Limits that remain: on such shares, and for share administrators, entries can still be forged. Recommended ACL on the triage folder: NOC group *Modify* on *This
  folder only* (create files), `CREATOR OWNER` *Full control* on *Subfolders and files only*, nobody
  else with write access (remove inherited *Users/Everyone* write), no "force user" mapping.
* **Privacy**: the files are plain JSON. Anyone who can open the share can read who acknowledged,
  snoozed, dismissed, muted, assigned or commented on which alert, and when. See *Trust* above for the
  recommended ACL.
* Switching stores offers to **copy this PC's current state** (the events that decide the current
  state, plus notes from the last 30 days) into the new store, keeping their ids and times so
  last-writer-wins still orders them correctly against teammates' events.

### `nodewatch_server` — Team server (planned)
Listed in Settings as "coming later"; selecting or constructing it is refused (HTTP 503). The module
docstring documents the design: one NodeWatch exposes `POST/GET /api/v1/team/events` over HTTPS,
clients authenticate with a per-user token kept in Windows Credential Manager (store manifests may not
declare secret fields — triage settings are a plain JSON file), and the client behaves exactly like
the shared folder (outbox while offline, incremental cursor reads, same fold).

## How to add a store

1. Create `app/services/triage/backends/<id>.py` (module name = `backend_id`; names starting with
   `_` are helpers and are not offered).
2. Define `MANIFEST = BackendManifest(backend_id=…, label=…, description=…, settings=(SettingField(…),),
   shared=True|False, maturity="preview")`. The Settings › Team triage form is drawn from it.
3. Define `BACKEND`, a `BaseBackend` subclass with `manifest = MANIFEST` implementing
   `append_many(events)` (persist validated events, or queue them while offline and call
   `self.ingest(...)` so they show at once), `append_many_imported(events)` (copy, keeping ids),
   `sync(force)` (read what is new, `self.ingest([(writer, raw), …])`), and the classmethods
   `clean_settings(values)` (raise `ValueError` with a readable message) and
   `test_settings(values, actor=…)` (a probe that changes nothing else). `health()` / `describe()` /
   `events_since()` / `current_state()` come from the base class. Raise `ReadOnlyError` (→ 403) or
   `StoreUnavailableError` (→ 503) for the user-facing failures.
4. Add tests next to `tests/test_triage_v01018.py`. Restart: the store appears in Settings.

## How to add a sink (ticketing / chat)

Create `app/services/triage/sinks/<name>.py` exposing `SINK`, an object with `sink_id` and
`on_event(event)` (or call `sinks.register(...)` at start-up). Only events made on this PC are
dispatched, so a team sharing one folder opens one ticket, not one per PC. Be idempotent by
`event["id"]`, queue slow work instead of blocking, keep credentials in Windows Credential Manager,
and treat anything that changes an external system as a confirmed, audited write. A failing sink is
logged and never fails the triage action. Example: a ServiceNow sink that opens an incident on
`assign` and adds a work note on `note`.

## HTTP API (dashboard router)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/dashboard/triage` | existing actions + `assign` (`assignee`: `me`, a user name or free text), `unassign`, `note` (`note` ≤ 500) for `incident_id` or `keys` |
| GET | `/api/dashboard/incidents/{id}` | now includes `team`: `activity` (who did what), `notes`, `assignees`, `actors`, `me`, `store` |
| GET | `/api/dashboard/triage/store` | manifests, active store, display name, status |
| POST | `/api/dashboard/triage/store` | `{backend, settings, display_name, copy_local}` |
| POST | `/api/dashboard/triage/store/test` | probe a store (shared folder: write, read back, delete a file) |
| GET | `/api/dashboard/triage/status` · POST `/api/dashboard/triage/sync` | sync status |
| GET | `/api/dashboard/triage/actors` | people seen in the store (assign picker) |
| GET | `/api/dashboard/triage/export` | full history as a JSON download |

## Limits today

* Shared logs are never deleted; at ~400 bytes per event a writer reaches one 2 MB segment after
  ~5,000 actions. Archiving old segments needs a compaction step (not built yet).
* The per-PC overlay keeps one entry per alert ever cleaned up locally.
* Identity is the Windows user name; NTFS permissions on the share are the only access control.
