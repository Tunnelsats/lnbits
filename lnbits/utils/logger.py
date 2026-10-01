import asyncio
import ipaddress
import logging
import re
import sys
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from lnbits.core.services import websocket_updater
from lnbits.helpers import get_db_vendor_name
from lnbits.settings import settings

if TYPE_CHECKING:
    from loguru import Record


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
    logger.add(
        lambda msg: serverlog_queue.put_nowait(msg),
        format=Formatter().format,
    )

    async def update_websocket_serverlog():
        msg = await serverlog_queue.get()
        await websocket_updater(super_user_hash, msg)

    return update_websocket_serverlog


# IP obfuscation (Tunnelsats fork):
# Client IP addresses must never end up in plain text in any log sink (stdout,
# log files, admin websocket server log). IPv4 addresses keep the first three
# octets (`203.0.113.xxx`), IPv6 addresses keep the first 48 bits
# (`2001:db8:1234:xxxx:xxxx:xxxx:xxxx:xxxx`). Loopback and unspecified addresses
# (e.g. `127.0.0.1`, `0.0.0.0`, `::1`) are left untouched as they carry no
# personal data and are useful for debugging.
_IPV4_CANDIDATE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6_CANDIDATE = re.compile(
    r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,5}){2,8}(?![\w:.])"
)
_IPV6_PORT_SUFFIX = re.compile(r"^(?P<ip>.+):(?P<port>\d{1,5})$")


def _parse_ip(
    value: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified:
        return None
    return ip


def _mask_ipv4(match: re.Match) -> str:
    candidate = match.group(0)
    if _parse_ip(candidate) is None:
        return candidate
    return candidate.rsplit(".", 1)[0] + ".xxx"


def _mask_ipv6_address(ip: ipaddress.IPv6Address) -> str:
    prefix = [format(int(group, 16), "x") for group in ip.exploded.split(":")[:3]]
    return ":".join([*prefix, "xxxx", "xxxx", "xxxx", "xxxx", "xxxx"])


def _mask_ipv6(match: re.Match) -> str:
    candidate = match.group(0)
    ip = _parse_ip(candidate)
    if isinstance(ip, ipaddress.IPv6Address):
        return _mask_ipv6_address(ip)
    # uvicorn logs IPv6 clients as `<ip>:<port>` without brackets
    with_port = _IPV6_PORT_SUFFIX.match(candidate)
    if with_port:
        ip = _parse_ip(with_port.group("ip"))
        if isinstance(ip, ipaddress.IPv6Address):
            return f"{_mask_ipv6_address(ip)}:{with_port.group('port')}"
    return candidate


def obfuscate_ips(message: str) -> str:
    """Mask the host part of every IPv4/IPv6 address found in `message`."""
    message = _IPV4_CANDIDATE.sub(_mask_ipv4, message)
    return _IPV6_CANDIDATE.sub(_mask_ipv6, message)


def obfuscate_ips_patcher(record: "Record") -> None:
    record["message"] = obfuscate_ips(record["message"])


def configure_logger() -> None:
    logger.remove()
    # applies to every sink, including the uvicorn logs routed through
    # `InterceptHandler` and the admin websocket server log
    logger.configure(patcher=obfuscate_ips_patcher)
    log_level: str = "DEBUG" if settings.debug else "INFO"
    formatter = Formatter()
    logger.add(sys.stdout, level=log_level, format=formatter.format)

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
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        logger.log(level, record.getMessage())
