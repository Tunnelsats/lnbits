import asyncio
import logging
import sys
from collections.abc import Callable
import re
from hashlib import sha256
from pathlib import Path

from loguru import logger

from lnbits.core.services import websocket_updater
from lnbits.helpers import get_db_vendor_name
from lnbits.settings import settings


def log_server_info():
    logger.info("LNbits Info")
    if settings.first_install:
        if settings.has_first_install_token_changed():
            logger.success("This is a first install token reset.")
        else:
            logger.success("This is a fresh install of LNbits.")

        if settings.first_install_token:
            logger.success(
                f"FIRST_INSTALL_TOKEN: `{settings.first_install_token}`. "
                "Please provide this token on /first_install."
            )
    logger.info(f"Version: {settings.version}")
    logger.info(f"Baseurl: {settings.lnbits_baseurl}")
    logger.info(f"Host: {settings.host}")
    logger.info(f"Port: {settings.port}")
    logger.info(f"Debug: {settings.debug}")
    logger.info(f"Site title: {settings.lnbits_site_title}")
    logger.info(f"Funding source: {settings.lnbits_backend_wallet_class}")
    logger.info(f"Data folder: {settings.lnbits_data_folder}")
    logger.info(f"Database: {get_db_vendor_name()}")
    logger.info(f"Service fee: {settings.lnbits_service_fee}")
    logger.info(f"Service fee max: {settings.lnbits_service_fee_max}")
    logger.info(f"Service fee wallet: {settings.lnbits_service_fee_wallet}")


def initialize_server_websocket_logger() -> Callable:
    super_user_hash = sha256(settings.super_user.encode("utf-8")).hexdigest()

    serverlog_queue: asyncio.Queue = asyncio.Queue()

    async def update_websocket_serverlog():
        while settings.lnbits_running:
            msg = await serverlog_queue.get()
            await websocket_updater(super_user_hash, msg)

    logger.add(
        lambda msg: serverlog_queue.put_nowait(msg),
        format=Formatter().format,
    )

    return update_websocket_serverlog


def hash_ip(ip: str) -> str:
    return sha256(ip.encode()).hexdigest()


def ip_hashing_filter(record: logging.LogRecord) -> bool:
    # IPv4 and IPv6 patterns
    ipv4_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    ipv6_pattern = r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::"
    ip_regex = re.compile(f"({ipv4_pattern}|{ipv6_pattern})")

    if record.args:
        record.args = tuple(
            hash_ip(arg) if isinstance(arg, str) and ip_regex.match(arg) else arg
            for arg in record.args
        )
    if record.msg:
        record.msg = ip_regex.sub(lambda match: hash_ip(match.group(0)), record.msg)
    return True


def configure_logger() -> None:
    logger.remove()
    log_level: str = "DEBUG" if settings.debug else "INFO"
    formatter = Formatter()
    logger.add(sys.stdout, level=log_level, format=formatter.format)

    # IP obfuscation
    # Access the 'uvicorn' and 'uvicorn.access' loggers
    uvicorn_logger = logging.getLogger("uvicorn")
    uvicorn_access_logger = logging.getLogger("uvicorn.access")

    # Add the IP hashing filter
    uvicorn_logger.addFilter(ip_hashing_filter)
    uvicorn_access_logger.addFilter(ip_hashing_filter)

    # Ensure the loggers are enabled
    uvicorn_logger.disabled = False
    uvicorn_access_logger.disabled = False

    if settings.enable_log_to_file:
        logger.add(
            Path(settings.lnbits_data_folder, "logs", "lnbits.log"),
            rotation=settings.log_rotation,
            retention=settings.log_retention,
            level="INFO",
            format=formatter.format,
        )
        logger.add(
            Path(settings.lnbits_data_folder, "logs", "debug.log"),
            rotation=settings.log_rotation,
            retention=settings.log_retention,
            level="DEBUG",
            format=formatter.format,
        )

    logging.getLogger("uvicorn").handlers = [InterceptHandler()]
    logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]
    logging.getLogger("uvicorn.error").handlers = [InterceptHandler()]
    logging.getLogger("uvicorn.error").propagate = False

    logging.getLogger("sqlalchemy").handlers = [InterceptHandler()]
    logging.getLogger("sqlalchemy.engine").handlers = [InterceptHandler()]
    logging.getLogger("sqlalchemy.engine").propagate = False
    logging.getLogger("sqlalchemy.engine.Engine").handlers = [InterceptHandler()]
    logging.getLogger("sqlalchemy.engine.Engine").propagate = False


class Formatter:
    def __init__(self):
        self.padding = 0
        self.minimal_fmt = (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> | <level>{level}</level> | "
            "<level>{message}</level>\n"
        )
        if settings.debug:
            self.fmt = (
                "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> | "
                "<level>{level: <4}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
                "<level>{message}</level>\n"
            )
        else:
            self.fmt = self.minimal_fmt

    def format(self, record):
        function = "{function}".format(**record)
        if function == "emit":  # uvicorn logs
            return self.minimal_fmt
        return self.fmt


class InterceptHandler(logging.Handler):
    def emit(self, record):
        ip_hashing_filter(record)
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        logger.log(level, record.getMessage())
