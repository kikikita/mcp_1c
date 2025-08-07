import logging
import os


def setup_logging() -> None:
    """Configure application-wide logging based on DEBUG env variable."""
    if getattr(setup_logging, "_configured", False):
        return
    debug = os.getenv("DEBUG", "false").lower() in {"1", "true", "yes"}
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    setup_logging._configured = True
