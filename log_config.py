import logging
import os


def setup_logging() -> None:
    """Configure application-wide logging and hide noisy third party loggers."""
    if getattr(setup_logging, "_configured", False):
        return

    debug = os.getenv("DEBUG", "false").lower() in {"1", "true", "yes"}
    level = logging.DEBUG if debug else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Silence overly verbose libraries so we only log high level steps
    for noisy in ("mcp.server", "mcp.client", "sse_starlette", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    setup_logging._configured = True
