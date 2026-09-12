#!/usr/bin/env python3
# -*- coding: utf8 -*-

"""Create, update, query, list, or delete Tencent Cloud DNSPod records."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import requests


__version__ = "2.0.0"
ENDPOINT = "https://dnspod.tencentcloudapi.com/"
HOST = "dnspod.tencentcloudapi.com"
SERVICE = "dnspod"
VERSION = "2021-03-23"
ALGORITHM = "TC3-HMAC-SHA256"
CONTENT_TYPE = "application/json"
DEFAULT_LINE = "\u9ed8\u8ba4"


class DNSPodError(RuntimeError):
    """A network transport or DNSPod service error."""

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.request_id = request_id


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hmac_sha256(key: bytes, value: str) -> bytes:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def make_authorization(
    secret_id: str,
    secret_key: str,
    payload: bytes,
    timestamp: int,
) -> str:
    """Build an API 3.0 (TC3-HMAC-SHA256) Authorization header."""
    date = dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).strftime("%Y-%m-%d")
    canonical_headers = f"content-type:{CONTENT_TYPE}\nhost:{HOST}\n"
    signed_headers = "content-type;host"
    canonical_request = "\n".join(
        ["POST", "/", "", canonical_headers, signed_headers, _sha256_hex(payload)]
    )
    credential_scope = f"{date}/{SERVICE}/tc3_request"
    string_to_sign = "\n".join(
        [
            ALGORITHM,
            str(timestamp),
            credential_scope,
            _sha256_hex(canonical_request.encode("utf-8")),
        ]
    )
    secret_date = _hmac_sha256(("TC3" + secret_key).encode("utf-8"), date)
    secret_service = _hmac_sha256(secret_date, SERVICE)
    secret_signing = _hmac_sha256(secret_service, "tc3_request")
    signature = hmac.new(
        secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return (
        f"{ALGORITHM} Credential={secret_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )


@dataclass
class DNSPodClient:
    secret_id: str
    secret_key: str
    token: Optional[str] = None
    timeout: float = 15.0
    requester: Callable[..., requests.Response] = requests.post
    clock: Callable[[], float] = time.time

    def call(self, action: str, parameters: Mapping[str, Any]) -> Dict[str, Any]:
        timestamp = int(self.clock())
        # Sign the exact bytes sent on the wire by using fixed JSON separators.
        payload = json.dumps(
            parameters, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        headers = {
            "Authorization": make_authorization(
                self.secret_id, self.secret_key, payload, timestamp
            ),
            "Content-Type": CONTENT_TYPE,
            "Host": HOST,
            "X-TC-Action": action,
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Version": VERSION,
        }
        if self.token:
            headers["X-TC-Token"] = self.token
        try:
            response = self.requester(
                ENDPOINT, data=payload, headers=headers, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise DNSPodError(f"Unable to connect to DNSPod: {exc}") from exc

        try:
            data = response.json()
        except ValueError as exc:
            if response.status_code >= 400:
                body = response.text.strip()
                detail = body or response.reason
                raise DNSPodError(f"HTTP {response.status_code}: {detail}") from exc
            raise DNSPodError("DNSPod returned an unreadable response") from exc

        result = data.get("Response") if isinstance(data, dict) else None
        if response.status_code >= 400 and not isinstance(result, dict):
            raise DNSPodError(
                f"HTTP {response.status_code}: {response.text.strip() or response.reason}"
            )
        if not isinstance(result, dict):
            raise DNSPodError("DNSPod returned an invalid response format")
        error = result.get("Error")
        if error:
            raise DNSPodError(
                error.get("Message", "DNSPod request failed"),
                error.get("Code"),
                result.get("RequestId"),
            )
        return result

    def list_records(
        self,
        domain: str,
        name: str,
        record_type: str,
        line: str,
        line_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        parameters: Dict[str, Any] = {
            "Domain": domain,
            "SubDomain": name,
            "RecordType": record_type,
            "RecordLine": line,
            "Limit": 3000,
            "ErrorOnEmpty": "no",
        }
        if line_id is not None:
            parameters["RecordLineId"] = line_id
        response = self.call("DescribeRecordList", parameters)
        records = response.get("RecordList", [])
        if not isinstance(records, list):
            raise DNSPodError("DNSPod returned an invalid record list")
        # Apply an exact client-side match because server-side filters may be broad.
        return [
            item
            for item in records
            if item.get("Name") == name
            and str(item.get("Type", "")).upper() == record_type.upper()
            and (
                str(item.get("LineId")) == line_id
                if line_id is not None
                else item.get("Line") == line
            )
        ]

    def list_all_records(self, domain: str) -> List[Dict[str, Any]]:
        response = self.call(
            "DescribeRecordList",
            {"Domain": domain, "Limit": 3000, "ErrorOnEmpty": "no"},
        )
        records = response.get("RecordList", [])
        if not isinstance(records, list):
            raise DNSPodError("DNSPod returned an invalid record list")
        return records

    def resolve_hostname(self, hostname: str) -> Tuple[str, str]:
        """Find the longest account domain that contains the full hostname."""
        response = self.call(
            "DescribeDomainList", {"Type": "ALL", "Offset": 0, "Limit": 3000}
        )
        domains = response.get("DomainList", [])
        if not isinstance(domains, list):
            raise DNSPodError("DNSPod returned an invalid domain list")
        hostname_lower = hostname.lower()
        matches = []
        for item in domains:
            name = item.get("Name") if isinstance(item, dict) else None
            if not isinstance(name, str):
                continue
            zone = name.strip().rstrip(".").lower()
            if hostname_lower == zone or hostname_lower.endswith("." + zone):
                matches.append(zone)
        if not matches:
            raise DNSPodError(f"No domain containing {hostname} was found in the account")
        domain = max(matches, key=len)
        name = "@" if hostname_lower == domain else hostname[: -(len(domain) + 1)]
        return domain, name

    def create_record(self, parameters: Mapping[str, Any]) -> Dict[str, Any]:
        return self.call("CreateRecord", parameters)

    def modify_record(self, parameters: Mapping[str, Any]) -> Dict[str, Any]:
        return self.call("ModifyRecord", parameters)

    def delete_record(self, domain: str, record_id: int) -> Dict[str, Any]:
        return self.call("DeleteRecord", {"Domain": domain, "RecordId": record_id})


def _selector_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--type",
        dest="record_type",
        default="A",
        help="Record type, such as A, AAAA, CNAME, TXT, or MX (default: A)",
    )
    parser.add_argument(
        "--line", default=DEFAULT_LINE, help="DNS route name (default: provider default)"
    )
    parser.add_argument("--line-id", help="DNS route ID; takes precedence over --line")


def _record_options(parser: argparse.ArgumentParser) -> None:
    _selector_options(parser)
    parser.add_argument(
        "--ttl", type=int, default=600, help="TTL from 1 to 604800 (default: 600)"
    )
    parser.add_argument(
        "--mx",
        type=int,
        default=0,
        help="MX/HTTPS/SVCB priority from 0 to 65535 (default: 0)",
    )
    parser.add_argument(
        "--weight", type=int, default=0, help="Weight from 0 to 100 (default: 0)"
    )
    parser.add_argument(
        "--status",
        choices=("ENABLE", "DISABLE"),
        default="ENABLE",
        help="Record status (default: ENABLE)",
    )
    parser.add_argument("--remark", default="", help="Record remark (default: empty)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnspod.py",
        description="Create, update, query, list, or delete Tencent Cloud DNSPod records",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0, help="Request timeout in seconds (default: 15)"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    set_command = commands.add_parser(
        "set", help="Update an existing record or create it if absent"
    )
    _record_options(set_command)
    set_command.add_argument("hostname", help="Full hostname, such as www.example.com")
    set_command.add_argument("value", help="Record value, such as 192.0.2.1")

    delete = commands.add_parser(
        "delete", aliases=("del", "rm"), help="Delete a record (aliases: del, rm)"
    )
    _selector_options(delete)
    delete.add_argument("hostname", help="Full hostname to delete")

    get = commands.add_parser("get", help="Query records for a hostname")
    _selector_options(get)
    get.add_argument("hostname", help="Full hostname to query")

    show = commands.add_parser(
        "ls", aliases=("show",), help="List all records in a domain (alias: show)"
    )
    show.add_argument("domain", help="Root domain, such as example.com")
    return parser


def _validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    target_name = "domain" if args.command in {"ls", "show"} else "hostname"
    target = getattr(args, target_name).strip().rstrip(".")
    setattr(args, target_name, target)
    if not target or "." not in target:
        parser.error(f"{target_name} must be a valid domain name")
    if hasattr(args, "record_type"):
        args.record_type = args.record_type.strip().upper()
    if hasattr(args, "ttl") and not 1 <= args.ttl <= 604800:
        parser.error("--ttl must be between 1 and 604800")
    if hasattr(args, "mx") and not 0 <= args.mx <= 65535:
        parser.error("--mx must be between 0 and 65535")
    if hasattr(args, "weight") and not 0 <= args.weight <= 100:
        parser.error("--weight must be between 0 and 100")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")


def _parameters(
    args: argparse.Namespace, record_id: Optional[int] = None
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "Domain": args.domain,
        "SubDomain": args.name,
        "RecordType": args.record_type,
        "RecordLine": args.line,
        "Value": args.value,
    }
    optional = {
        "RecordLineId": args.line_id,
        "TTL": args.ttl,
        "MX": args.mx,
        "Weight": args.weight,
        "Status": args.status,
        "Remark": args.remark,
        "RecordId": record_id,
    }
    result.update({key: value for key, value in optional.items() if value is not None})
    return result


def _find_record_id(client: DNSPodClient, args: argparse.Namespace) -> Optional[int]:
    records = client.list_records(
        args.domain, args.name, args.record_type, args.line, args.line_id
    )
    if not records:
        return None
    if len(records) > 1:
        ids = ", ".join(str(item.get("RecordId")) for item in records)
        raise DNSPodError(
            f"Multiple records matched (IDs: {ids}); specify --line or --line-id"
        )
    record_id = records[0].get("RecordId")
    if not isinstance(record_id, int):
        raise DNSPodError("The matching record has no valid RecordId")
    return record_id


def execute(client: DNSPodClient, args: argparse.Namespace) -> Dict[str, Any]:
    if args.command in {"ls", "show"}:
        return {
            "operation": "listed",
            "domain": args.domain,
            "records": client.list_all_records(args.domain),
        }

    args.domain, args.name = client.resolve_hostname(args.hostname)

    if args.command == "get":
        return {
            "operation": "fetched",
            "domain": args.domain,
            "records": client.list_records(
                args.domain,
                args.name,
                args.record_type,
                args.line,
                args.line_id,
            ),
        }

    record_id = _find_record_id(client, args)
    if args.command in {"delete", "del", "rm"}:
        if record_id is None:
            raise DNSPodError("No matching record was found to delete")
        response = client.delete_record(args.domain, record_id)
        return {
            "operation": "deleted",
            "record_id": record_id,
            "request_id": response.get("RequestId"),
        }
    if record_id is None:
        response = client.create_record(_parameters(args))
        operation = "created"
    else:
        response = client.modify_record(_parameters(args, record_id))
        operation = "modified"
    return {
        "operation": operation,
        "record_id": response.get("RecordId", record_id),
        "request_id": response.get("RequestId"),
    }


def _display_width(value: str) -> int:
    """Return the number of terminal columns normally occupied by a string."""
    return sum(
        0
        if unicodedata.combining(character)
        else 2
        if unicodedata.east_asian_width(character) in {"F", "W"}
        else 1
        for character in value
    )


def _pad_column(value: str, width: int) -> str:
    return value + " " * (width - _display_width(value))


def _print_records(domain: str, records: Sequence[Mapping[str, Any]]) -> None:
    rows = [("TYPE", "NAME", "VALUE", "LINE", "TTL", "STATUS")]
    for record in records:
        name = str(record.get("Name", ""))
        hostname = domain if name == "@" else f"{name}.{domain}"
        rows.append(
            tuple(
                str(value)
                for value in (
                    record.get("Type", ""),
                    hostname,
                    record.get("Value", ""),
                    record.get("Line", ""),
                    record.get("TTL", ""),
                    record.get("Status", ""),
                )
            )
        )

    widths = [
        max(_display_width(row[index]) for row in rows)
        for index in range(len(rows[0]))
    ]
    for row in rows:
        print(
            "  ".join(
                _pad_column(value, widths[index])
                if index < len(row) - 1
                else value
                for index, value in enumerate(row)
            )
        )


def _credential(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate(parser, args)
    secret_id = _credential("TENCENTCLOUD_SECRET_ID")
    secret_key = _credential("TENCENTCLOUD_SECRET_KEY")
    if not secret_id or not secret_key:
        parser.error(
            "Set the TENCENTCLOUD_SECRET_ID and TENCENTCLOUD_SECRET_KEY "
            "environment variables"
        )

    client = DNSPodClient(
        secret_id,
        secret_key,
        token=_credential("TENCENTCLOUD_SESSION_TOKEN"),
        timeout=args.timeout,
    )
    try:
        result = execute(client, args)
    except DNSPodError as exc:
        prefix = f"[{exc.code}] " if exc.code else ""
        suffix = f" (RequestId: {exc.request_id})" if exc.request_id else ""
        print(f"Error: {prefix}{exc}{suffix}", file=sys.stderr)
        return 1

    if result["operation"] in {"fetched", "listed"}:
        _print_records(result["domain"], result["records"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
