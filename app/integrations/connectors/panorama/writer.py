"""Panorama change module — DESIGN ONLY, NOT IMPLEMENTED.

Nothing in this file talks to Panorama. It exists so the future "push a change through Panorama"
feature has a fixed place and a reviewed plan, and so the read connector stays strictly read-only
(``client.assert_read_only`` refuses every request below; the writer will get its own client).

Why through Panorama: most companies push firewall configuration from Panorama (device groups for
policy/objects, templates/template stacks for network/device settings). Editing firewalls directly
would be overwritten by the next push, so NodeWatch will change Panorama's candidate config and push.

Intended flow (PAN-OS and Panorama API guide, docs.paloaltonetworks.com — "Configuration API",
"Commit Configuration (API)", "Asynchronous and Synchronous Requests to the PAN-OS XML API"):

1. Scope + permissions. The change is described as NodeWatch domain intent (e.g. "allow tcp/443 from
   zone A to B for host X on device group DG"), mapped to an XPath under
   ``/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='<DG>']/…``
   (policy/objects) or ``…/template/entry[@name='<T>']/config/…`` (network). A separate admin role
   with XML API *Configuration* + *Commit* rights is required; the read-only key used today must keep
   only *Operational Requests*.
2. Lock. ``type=op&cmd=<request><config-lock><add><comment>NodeWatch</comment></add></config-lock></request>``
   (and commit-lock) so two admins cannot interleave; always released in ``finally``.
3. Snapshot for rollback. Save the running config as a named file:
   ``type=op&cmd=<save><config><to>nodewatch-pre-<audit id>.xml</to></config></save>``.
4. Edit candidate. ``type=config&action=set`` (add) / ``action=edit`` (replace) / ``action=delete``
   with ``xpath=`` and ``element=``; never ``multi-config`` without a per-step audit entry.
5. Validate + preview. ``type=op&cmd=<validate><full/></validate>`` (async job → poll
   ``<show><jobs><id>N</id></jobs></show>`` until FIN, result OK) and show the diff of candidate vs
   running (``<show><config><list><change-summary/></list></config></show>``, or the config audit diff)
   in the NodeWatch confirm dialog, exactly like Port Toolkit / Mist writes: nothing is committed
   until the user confirms (``confirmed is True``).
6. Commit to Panorama. ``type=commit&cmd=<commit><description>NodeWatch …</description></commit>``
   (optionally ``<partial><admin><member>…</member></admin></partial>``) → job id → poll to FIN/OK.
7. Push to firewalls. ``type=commit&action=all&cmd=<commit-all><shared-policy><device-group><entry
   name='<DG>'/></device-group></shared-policy></commit-all>`` (``<template>`` / ``<template-stack>`` for
   network changes) → job id → poll; per-firewall results come back in the job's devices list.
8. Audit. Every step (snapshot name, XPath, element hash, commit/push job ids, per-firewall result)
   is written through ``AuditService`` with the confirming user, before and after.
9. Rollback. On a failed validate: revert the candidate (``<revert><config/></revert>``). On a failed
   push or user request: ``<load><config><from>nodewatch-pre-<audit id>.xml</from></config></load>``,
   commit, commit-all — again confirmed and audited.

Only then would the connector declare a ``.write`` capability (contracts: names ending in ``.write``),
which also flips ``ProviderDescriptor.read_only`` to False.
"""

from __future__ import annotations

from typing import Any

from app.integrations.connectors.panorama.client import ReadOnlyViolation

PLANNED_OPERATIONS = (
    "config-lock",
    "save-snapshot",
    "config.set",
    "config.edit",
    "config.delete",
    "validate",
    "commit",
    "commit-all",
    "rollback",
)


class PanoramaWriter:
    """Placeholder for the future change module. Every method refuses."""

    implemented = False

    def __init__(self, *_: Any, **__: Any) -> None:
        pass

    def plan(self, *_: Any, **__: Any) -> Any:
        raise ReadOnlyViolation("Panorama changes are not implemented yet (design in panorama/writer.py)")

    preview = validate = apply = commit = push = rollback = plan
