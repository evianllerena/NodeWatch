# NodeWatch pilot — scope sheet (agree with the customer, then record in the plan)

The report requires the pilot's scope to be written down and agreed before it starts. Fill this in with the
customer; every later change to it goes in the plan's change log first.

## Connections and tenants

| Vendor / product | Host / org | Account & role | Read-only? | In pilot? |
|---|---|---|---|---|
| Juniper Mist | org id: ______ | API token role: ______ | ______ | ______ |
| Palo Alto (Strata / Device Security) | tenant (TSG): ______ | service account role: ______ | ______ | ______ |
| Panorama | base URL: ______ | admin role: ______ | ______ | ______ |
| FortiGate | base URL / VDOM: ______ | REST admin profile: ______ | ______ | ______ |
| Silver Peak (EdgeConnect) | orchestrator URL: ______ | account role: ______ | ______ | ______ |
| SNMP | targets: ______ | v2c/v3 creds: ______ | read-only | ______ |

The pilot customer has one connection per vendor (a second customer may have more; NodeWatch supports adding
more connections of a connector — see docs and `POST /api/v1/connectors/{id}/connections`).

## Mist token

- Scope the Mist API token to the pilot sites only (not the whole org) where the customer can.
- Write-capable only if the customer wants NodeWatch to make changes (see below); otherwise read-only.

## Writes enabled for the pilot (default: none)

NodeWatch changes nothing unless the connection's account is allowed to and the action is turned on. Decide per
action:

- [ ] Port operations (bounce / cable test) — Mist
- [ ] Apply a Virtual Chassis change — Mist
- [ ] Restore a configuration backup — Mist
- [ ] Acknowledge an alarm in the source — Mist

Anything left unchecked stays off for the pilot.

## Shared triage folder (if used)

When several PCs share a triage folder and NodeWatch cannot confirm a file's Windows owner, it shows "names not
verified". Decide the stance:

- [ ] Use a shared folder NodeWatch can verify owners on, or
- [ ] Accept the "names not verified" notice, or
- [ ] Each PC keeps its own local triage (no sharing) for the pilot.

## Definition of done (from the report) — confirm before go-live

- [ ] Both review-report Mediums closed; Lows swept. (Done in the build; confirm on the pilot build.)
- [ ] Test suite + coverage from a release build. (CI, every release.)
- [ ] Runtime pentest complete, findings triaged. (See docs/PENTEST.md.)
- [ ] This scope sheet agreed and recorded.

## Sign-off

Customer: ________________  Date: ______    BWN: ________________  Date: ______
