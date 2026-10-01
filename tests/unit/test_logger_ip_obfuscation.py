import logging

import pytest
from loguru import logger

from lnbits.utils.logger import InterceptHandler, obfuscate_ips, obfuscate_ips_patcher


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        # uvicorn access log, IPv4 with port
        (
            '203.0.113.42:51234 - "GET /api/v1/wallet HTTP/1.1" 200',
            '203.0.113.xxx:51234 - "GET /api/v1/wallet HTTP/1.1" 200',
        ),
        ("client 10.8.0.17 connected.", "client 10.8.0.xxx connected."),
        ("from 1.2.3.4, 5.6.7.8", "from 1.2.3.xxx, 5.6.7.xxx"),
        # IPv4-mapped IPv6
        ("::ffff:198.51.100.7 hit", "::ffff:198.51.100.xxx hit"),
        # IPv6
        (
            "2001:db8:1234:5678:9abc:def0:1234:5678 - GET",
            "2001:db8:1234:xxxx:xxxx:xxxx:xxxx:xxxx - GET",
        ),
        ("peer 2a01:4f8::1 ok", "peer 2a01:4f8:0:xxxx:xxxx:xxxx:xxxx:xxxx ok"),
        # uvicorn access log, IPv6 with port (no brackets)
        (
            '2a01:4f8:c17:1::2:51234 - "GET / HTTP/1.1" 200',
            '2a01:4f8:c17:xxxx:xxxx:xxxx:xxxx:xxxx:51234 - "GET / HTTP/1.1" 200',
        ),
        # loopback / unspecified are kept
        ("Host: 0.0.0.0", "Host: 0.0.0.0"),
        ("127.0.0.1:5000 - GET", "127.0.0.1:5000 - GET"),
        ("::1 - GET", "::1 - GET"),
        # no false positives
        ("Version: 1.6.2", "Version: 1.6.2"),
        ("v1.2.3.4", "v1.2.3.4"),
        ("1.2.3.4.5", "1.2.3.4.5"),
        ("999.1.1.1", "999.1.1.1"),
        ("2026-10-01 20:41:31.12 | INFO", "2026-10-01 20:41:31.12 | INFO"),
        ("12:30:45 elapsed", "12:30:45 elapsed"),
        # anything that parses as a valid IPv6 address is masked
        ("ab12::cd34 is a hash", "ab12:0:0:xxxx:xxxx:xxxx:xxxx:xxxx is a hash"),
    ],
)
def test_obfuscate_ips(message: str, expected: str):
    assert obfuscate_ips(message) == expected


def test_uvicorn_logs_are_obfuscated():
    messages: list[str] = []
    logger.configure(patcher=obfuscate_ips_patcher)
    sink_id = logger.add(lambda msg: messages.append(msg.record["message"]))
    try:
        record = logging.LogRecord(
            name="uvicorn.access",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg='%s - "%s %s HTTP/%s" %d',
            args=("203.0.113.42:51234", "GET", "/", "1.1", 200),
            exc_info=None,
        )
        InterceptHandler().emit(record)
    finally:
        logger.remove(sink_id)
        logger.configure(patcher=lambda _: None)

    assert messages == ['203.0.113.xxx:51234 - "GET / HTTP/1.1" 200']
