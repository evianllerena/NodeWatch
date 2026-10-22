"""Shared Mist event trigger/clear correlation used by the NOC and future tools."""

EVENT_PAIRS = {
    "AP_CONFIG_FAILED": {"AP_CONFIGURED", "AP_RECONFIGURED"},
    "AP_DISCONNECTED": {"AP_CONNECTED"},
    "AP_PORT_DOWN": {"AP_PORT_UP"},
    "AP_RADSEC_FAILURE": {"AP_RADSEC_RECOVERY"},
    "AP_UPGRADE_FAILED": {"AP_UPGRADED"},
    "SW_DISCONNECTED": {"SW_CONNECTED"},
    "SW_CONFIG_FAILED": {"SW_CONFIGURED", "SW_RECONFIGURED"},
    "SW_CONFIG_LOCK_FAILED": {"SW_CONFIGURED", "SW_RECONFIGURED"},
    "SW_CONFIG_ERROR_ADDTL_COMMAND": {"SW_CONFIGURED", "SW_RECONFIGURED"},
    "SW_UPGRADE_FAILED": {"SW_UPGRADED"},
    "SW_ZTP_FAILED": {"SW_ZTP_FINISHED"},
    "SW_PORT_DOWN": {"SW_PORT_UP"},
    "SW_PORT_BPDU_BLOCKED": {"SW_PORT_BPDU_ERROR_CLEARED"},
    "SW_VC_PORT_DOWN": {"SW_VC_PORT_UP"},
    "SW_LACPD_TIMEOUT": {"SW_LACPD_TIMEOUT_CLEARED"},
    "SW_LOOP_DETECTED": {"SW_LOOP_CLEARED"},
    "SW_BGP_NEIGHBOR_DOWN": {"SW_BGP_NEIGHBOR_UP"},
    "SW_OSPF_NEIGHBOR_DOWN": {"SW_OSPF_NEIGHBOR_UP"},
    "SW_BFD_SESSION_DISCONNECTED": {"SW_BFD_SESSION_ESTABLISHED"},
    "SW_EVPN_CORE_ISOLATED": {"SW_EVPN_CORE_ISOLATION_CLEARED"},
    "SW_ALARM_CHASSIS_FAN": {"SW_ALARM_CHASSIS_FAN_CLEAR"},
    "SW_ALARM_CHASSIS_HOT": {"SW_ALARM_CHASSIS_HOT_CLEAR"},
    "SW_ALARM_CHASSIS_HUMIDITY": {"SW_ALARM_CHASSIS_HUMIDITY_CLEAR"},
    "SW_ALARM_CHASSIS_MGMT_LINK_DOWN": {"SW_ALARM_CHASSIS_MGMT_LINK_DOWN_CLEAR"},
    "SW_ALARM_CHASSIS_PARTITION": {"SW_ALARM_CHASSIS_PARTITION_CLEAR"},
    "SW_ALARM_CHASSIS_PEM": {"SW_ALARM_CHASSIS_PEM_CLEAR"},
    "SW_ALARM_CHASSIS_POE": {"SW_ALARM_CHASSIS_POE_CLEAR"},
    "SW_ALARM_CHASSIS_PSU": {"SW_ALARM_CHASSIS_PSU_CLEAR"},
    "SW_ALARM_IOT_SET": {"SW_ALARM_IOT_CLEAR"},
    "SW_ALARM_VIRTUAL_CHASSIS_VERSION_MISMATCH": {"SW_ALARM_VIRTUAL_CHASSIS_VERSION_MISMATCH_CLEAR"},
    "SW_VC_IN_TRANSITION": {"SW_VC_STABLE"},
    "SW_DDOS_PROTOCOL_VIOLATION_SET": {"SW_DDOS_PROTOCOL_VIOLATION_CLEAR"},
    "SW_FPC_POWER_OFF": {"SW_FPC_POWER_ON"},
    "SW_MAC_LEARNING_STOPPED": {"SW_MAC_LEARNING_RESUMED"},
    "SW_MAC_LIMIT_EXCEEDED": {"SW_MAC_LIMIT_RESET"},
    "GW_DISCONNECTED": {"GW_CONNECTED"},
    "GW_CONFIG_FAILED": {"GW_CONFIGURED", "GW_RECONFIGURED"},
    "GW_CONFIG_LOCK_FAILED": {"GW_CONFIGURED", "GW_RECONFIGURED"},
    "GW_CONFIG_ERROR_ADDTL_COMMAND": {"GW_CONFIGURED", "GW_RECONFIGURED"},
    "GW_UPGRADE_FAILED": {"GW_UPGRADED"},
    "GW_ZTP_FAILED": {"GW_ZTP_FINISHED"},
    "GW_PORT_DOWN": {"GW_PORT_UP"},
    "GW_ARP_UNRESOLVED": {"GW_ARP_RESOLVED"},
    "GW_DHCP_UNRESOLVED": {"GW_DHCP_RESOLVED"},
    "GW_TUNNEL_DOWN": {"GW_TUNNEL_UP"},
    "GW_BGP_NEIGHBOR_DOWN": {"GW_BGP_NEIGHBOR_UP"},
    "GW_OSPF_NEIGHBOR_DOWN": {"GW_OSPF_NEIGHBOR_UP"},
    "GW_CONDUCTOR_DISCONNECTED": {"GW_CONDUCTOR_CONNECTED"},
    "GW_VPN_PATH_DOWN": {"GW_VPN_PATH_UP"},
    "GW_VPN_PEER_DOWN": {"GW_VPN_PEER_UP"},
    "GW_HA_CONTROL_LINK_DOWN": {"GW_HA_CONTROL_LINK_UP"},
    "GW_HA_HEALTH_WEIGHT_LOW": {"GW_HA_HEALTH_WEIGHT_RECOVERY"},
}


def event_type(event: dict) -> str:
    return str(event.get("type") or event.get("event_type") or event.get("type_code") or "").upper()


def event_key(event: dict) -> tuple:
    return (
        event.get("site_id"),
        event.get("mac") or event.get("device_id") or event.get("device"),
        event.get("port_id")
        or event.get("port")
        or event.get("fru_slot")
        or event.get("protocol_name")
        or event.get("neighbor")
        or event.get("component"),
    )


def event_timestamp(event: dict) -> float:
    """Event time as epoch seconds. Accepts seconds, milliseconds or ISO-8601 strings."""
    from datetime import datetime

    value = event.get("timestamp") or event.get("time") or 0
    try:
        number = float(value)
    except (TypeError, ValueError):
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    return number / 1000.0 if number > 10_000_000_000 else number


def correlate_event_states(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (open_triggers, recent_events_with_state).

    ``_state`` is "open" for a trigger without a later clear, "cleared" for a clear
    event, and "info" otherwise. ``_matched_trigger`` says whether a clear event
    closed a trigger seen in this window (it may have opened before the window).
    """
    ordered = sorted(events, key=event_timestamp)
    reverse: dict[str, set[str]] = {}
    for trigger, clears in EVENT_PAIRS.items():
        for clear in clears:
            reverse.setdefault(clear, set()).add(trigger)

    open_by_key: dict[tuple, dict] = {}
    state_rows: list[dict] = []
    for event in ordered:
        etype = event_type(event)
        base = event_key(event)
        if etype in EVENT_PAIRS:
            open_by_key[(etype, base)] = event
            state_rows.append({**event, "_state": "open", "_event_type": etype})
            continue
        if etype in reverse:
            matched = False
            for trigger in reverse[etype]:
                if open_by_key.pop((trigger, base), None) is not None:
                    matched = True
            state_rows.append({**event, "_state": "cleared", "_matched_trigger": matched, "_event_type": etype})
        else:
            state_rows.append({**event, "_state": "info", "_event_type": etype})
    return (
        sorted(open_by_key.values(), key=event_timestamp, reverse=True),
        sorted(state_rows, key=event_timestamp, reverse=True),
    )
