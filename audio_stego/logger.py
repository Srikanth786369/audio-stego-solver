"""
Logging configuration for Audio Stego Solver.
"""

import logging
from pathlib import Path


def setup_logger(
    name: str = "audio_stego",
    log_dir: str = "logs",
    log_file: str = "run.log",
    level: int = logging.DEBUG,
    verbose: bool = False,
) -> logging.Logger:
    """
    Set up and return a configured logger.

    Args:
        name: Logger name
        log_dir: Directory for log files
        log_file: Log filename
        level: Logging level
        verbose: If True, also log DEBUG to console

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers
    logger.handlers.clear()

    # Create log directory if needed
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # File handler - always DEBUG level
    file_handler = logging.FileHandler(log_path / log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler - only WARNING+ unless verbose
    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_formatter = logging.Formatter("%(levelname)-8s | %(message)s")
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger


def get_logger(name: str = "audio_stego") -> logging.Logger:
    """Get an existing logger by name."""
    return logging.getLogger(name)
