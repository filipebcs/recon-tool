import re

DNS_NAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
)

def is_valid_hostname(value: str) -> bool:
    if "@" in value:
        return False
    if " " in value:
        return False
    return bool(DNS_NAME_REGEX.match(value))