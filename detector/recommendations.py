def get_recommendation(detection_type: str) -> str:
    mapping = {
        "port_scan": "Verify whether the source is an authorized scanner, review exposed services, and confirm whether the host should be allowed to probe internal ports.",
        "brute_force": "Review authentication logs, investigate the source IP, and confirm rate limiting and account lockout policies are in place.",
        "anomaly": "Compare the activity against normal usage, investigate related events, and validate whether the traffic is expected for the environment.",
        "vpn_auth_failure": "Review VPN access logs, confirm whether MFA was challenged, and validate user identity and access policies.",
        "vpn_repeated_disconnect": "Check whether the user or endpoint is repeatedly reconnecting due to a configuration issue or suspicious activity.",
        "vpn_unusual_login": "Confirm the user and device state, review whether the login time is expected, and validate travel or MFA policies.",
        "default": "Investigate the event in context, confirm the source activity, and review related logs before making changes.",
    }
    return mapping.get(detection_type, mapping["default"]) 
