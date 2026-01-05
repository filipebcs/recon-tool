import logging
from typing import Optional


def setup_logger(
    name: str = "recon",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Configure a reusable structured logger.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s"
    )

    if not logger.handlers:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger
