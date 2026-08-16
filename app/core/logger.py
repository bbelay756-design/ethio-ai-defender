"""
Security and Application Logging for ETHIO-AI Defender.
"""

import sys
import logging
from logging.handlers import RotatingFileHandler
from app.core.config import settings


def setup_logger(name: str = "ethio_ai_defender") -> logging.Logger:
    """
    Configures and returns a structured logger with both console
    and rotating file output handlers.
    """
    logger = logging.getLogger(name)

    # Avoid duplicate handlers if setup_logger is invoked repeatedly
    if logger.handlers:
        return logger

    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(log_level)

    # Standardized security log format
    log_format = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s:%(filename)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    console_handler.setLevel(log_level)
    logger.addHandler(console_handler)

    # Rotating File Handler (Max 10MB per file, keeping 5 backup rotations)
    try:
        settings.ensure_directories()
        file_handler = RotatingFileHandler(
            settings.LOG_FILE,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(log_format)
        file_handler.setLevel(log_level)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not initialize file log handler: {e}")

    return logger


# Default application-wide logger
logger = setup_logger()
