"""
No-op logging shim.

Earlier builds shipped a file logger here that wrote to the SD card's boot
partition. That is gone: a signing device must never persist usage data. This
shim exists only to OVERRIDE the logger baked into older fork-built images via
the inject overlay — anything that still imports it gets a logger that goes
nowhere and never touches storage.
"""

import logging


def get_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        log.addHandler(logging.NullHandler())
    return log
