def normalize_domain(domain: str) -> str:
    """
    example.com.br -> example-com-br
    """
    return domain.strip().lower().replace(".", "-")
