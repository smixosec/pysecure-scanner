import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def validate_ip(ip_str: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False
