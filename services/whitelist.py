# A mapping of whitelisted IP addresses to their owner or description.
# If an IP is found in this list, automated blocking actions will be safely overridden.

WHITELISTED_IPS = {
    "192.168.1.10": "CEO (John Doe)",
    "192.168.1.11": "CTO (Jane Smith)",
    "192.168.1.12": "CFO (Alice Johnson)",
    "192.168.1.50": "SOC Internal Office IP",
    "127.0.0.1": "Localhost / Internal System",
    # TODO: Add your actual own IP and executive IPs here
}
