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
        records: List[Dict[str, Any]] = []
        while True:
            response = self.call(
                "DescribeRecordList",
                {"Domain": domain, "Offset": len(records), "Limit": 3000, "ErrorOnEmpty": "no"},
            )
            batch = response.get("RecordList", [])
            if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
                raise DNSPodError("DNSPod returned an invalid record list")
            records.extend(batch)
            if len(batch) < 3000:
                return records

    def list_domains(self) -> List[Dict[str, Any]]:
        domains: List[Dict[str, Any]] = []
        while True:
            response = self.call(
                "DescribeDomainList", {"Type": "ALL", "Offset": len(domains), "Limit": 3000}
            )
            batch = response.get("DomainList", [])
            if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
                raise DNSPodError("DNSPod returned an invalid domain list")
            domains.extend(batch)
            if len(batch) < 3000:
                return domains

    def find_records_by_id(
        self, record_ids: Sequence[int]
    ) -> Dict[int, Tuple[str, Dict[str, Any]]]:
        pending = set(record_ids)
        found: Dict[int, Tuple[str, Dict[str, Any]]] = {}
        for item in self.list_domains():
            domain = item.get("Name")
            if not isinstance(domain, str) or not domain:
                continue
            for record in self.list_all_records(domain):
                record_id = record.get("RecordId")
                if record_id in pending:
                    found[record_id] = (domain, record)
                    pending.remove(record_id)
            if not pending:
                break
        return found

    def resolve_hostname(self, hostname: str) -> Tuple[str, str]:
        """Find the longest account domain that contains the full hostname."""
        hostname_lower = hostname.lower()
        matches = []
        for item in self.list_domains():
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


def _selector_options(parser: argparse.ArgumentParser, update: bool = False) -> None:
    parser.add_argument(
        "--type",
        dest="record_type",
        default=None if update else "A",
        help="Record type, such as A, AAAA, CNAME, TXT, or MX "
        + ("(unchanged when omitted)" if update else "(default: A)"),
    )
    parser.add_argument(
        "--line", default=None if update else DEFAULT_LINE,
        help="DNS route name "
        + ("(unchanged when omitted)" if update else "(default: provider default)"),
    )
    parser.add_argument("--line-id", help="DNS route ID; takes precedence over --line")


def _record_options(parser: argparse.ArgumentParser, update: bool = False) -> None:
    _selector_options(parser, update=update)
    parser.add_argument(
        "--ttl", type=int, default=None if update else 600,
        help="TTL from 1 to 604800 "
        + ("(unchanged when omitted)" if update else "(default: 600)"),
    )
    parser.add_argument(
        "--mx",
        type=int,
        default=None if update else 0,
        help="MX/HTTPS/SVCB priority from 0 to 65535 "
        + ("(unchanged when omitted)" if update else "(default: 0)"),
    )
    parser.add_argument(
        "--weight", type=int, default=None if update else 0,
        help="Weight from 0 to 100 "
        + ("(unchanged when omitted)" if update else "(default: 0)"),
    )
    parser.add_argument(
        "--status",
        choices=("ENABLE", "DISABLE"),
        default=None if update else "ENABLE",
        help="Record status "
        + ("(unchanged when omitted)" if update else "(default: ENABLE)"),
    )
    parser.add_argument(
        "--remark", default=None if update else "",
        help="Record remark "
        + ("(unchanged when omitted)" if update else "(default: empty)"),
    )


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

    add = commands.add_parser("add", help="Create a new record")
    _record_options(add)
    add.add_argument("hostname", help="Full hostname, such as www.example.com")
    add.add_argument("value", help="Record value, such as 192.0.2.1")

    set_command = commands.add_parser("set", help="Update an existing record by ID")
    _record_options(set_command, update=True)
    set_command.add_argument("record_id", metavar="id", type=int, help="Record ID from ls")
    set_command.add_argument("value", help="Record value, such as 192.0.2.1")

    delete = commands.add_parser(
        "delete", aliases=("del", "rm"), help="Delete records by ID (aliases: del, rm)"
    )
    delete.add_argument("record_ids", metavar="id", type=int, nargs="+", help="Record IDs from ls")

    get = commands.add_parser("get", help="Query records for a hostname")
    _selector_options(get)
    get.add_argument("hostname", help="Full hostname to query")

    show = commands.add_parser(
        "ls", aliases=("show",), help="List account domains or records in a domain (alias: show)"
    )
    show.add_argument(
        "domain", nargs="?", help="Root domain, such as example.com; omit to list account domains"
    )
    return parser


def _validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.command in {"add", "get", "ls", "show"}:
        target_name = "domain" if args.command in {"ls", "show"} else "hostname"
        target = getattr(args, target_name)
        if target is not None:
            target = target.strip().rstrip(".")
            setattr(args, target_name, target)
            if not target or "." not in target:
                parser.error(f"{target_name} must be a valid domain name")
    if hasattr(args, "record_id") and args.record_id <= 0:
        parser.error("record ID must be a positive integer")
    if hasattr(args, "record_ids") and any(record_id <= 0 for record_id in args.record_ids):
        parser.error("record IDs must be positive integers")
    if getattr(args, "record_type", None) is not None:
        args.record_type = args.record_type.strip().upper()
        if not args.record_type:
            parser.error("--type cannot be empty")
    for option in ("line", "line_id"):
        if getattr(args, option, None) is not None:
            value = getattr(args, option).strip()
            if not value:
                parser.error(f"--{option.replace('_', '-')} cannot be empty")
            setattr(args, option, value)
    if getattr(args, "ttl", None) is not None and not 1 <= args.ttl <= 604800:
        parser.error("--ttl must be between 1 and 604800")
    if getattr(args, "mx", None) is not None and not 0 <= args.mx <= 65535:
        parser.error("--mx must be between 0 and 65535")
    if getattr(args, "weight", None) is not None and not 0 <= args.weight <= 100:
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


def execute(client: DNSPodClient, args: argparse.Namespace) -> Dict[str, Any]:
    if args.command in {"ls", "show"}:
        if args.domain is None:
            return {"operation": "domains_listed", "domains": client.list_domains()}
        return {
            "operation": "listed",
            "domain": args.domain,
            "records": client.list_all_records(args.domain),
        }

    if args.command in {"delete", "del", "rm"}:
        records = client.find_records_by_id(args.record_ids)
        deleted = []
        for record_id in dict.fromkeys(args.record_ids):
            try:
                if record_id not in records:
                    raise DNSPodError("No matching record was found")
                domain, _ = records[record_id]
                client.delete_record(domain, record_id)
            except DNSPodError as exc:
                detail = f"Unable to delete record {record_id}: {exc}"
                if deleted:
                    detail += f"; already deleted: {', '.join(map(str, deleted))}"
                raise DNSPodError(detail, exc.code, exc.request_id) from exc
            deleted.append(record_id)
        return {"operation": "deleted", "record_ids": deleted}

    if args.command == "set":
        records = client.find_records_by_id([args.record_id])
        if args.record_id not in records:
            raise DNSPodError(f"No matching record was found for ID {args.record_id}")
        args.domain, record = records[args.record_id]
        for field in ("Name", "Type", "Line", "TTL", "Status"):
            if record.get(field) is None or str(record[field]) == "":
                raise DNSPodError(f"The record response has no valid {field}")
        args.name = record["Name"]
        if args.line is None and args.line_id is None:
            args.line_id = record.get("LineId")
        for option, field in (
            ("record_type", "Type"), ("line", "Line"), ("ttl", "TTL"),
            ("mx", "MX"), ("weight", "Weight"), ("status", "Status"), ("remark", "Remark"),
        ):
            if getattr(args, option) is None:
                setattr(args, option, record.get(field))
        response = client.modify_record(_parameters(args, args.record_id))
        return {
            "operation": "modified", "record_id": args.record_id,
            "request_id": response.get("RequestId"),
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

    response = client.create_record(_parameters(args))
    return {
        "operation": "created",
        "record_id": response.get("RecordId"),
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


def _print_domains(domains: Sequence[Mapping[str, Any]]) -> None:
    print("DOMAIN")
    for domain in domains:
        print(domain.get("Name", ""))


def _print_records(domain: str, records: Sequence[Mapping[str, Any]]) -> None:
    rows = [("ID", "TYPE", "NAME", "VALUE", "LINE", "TTL", "STATUS")]
    for record in records:
        name = str(record.get("Name", ""))
        hostname = domain if name == "@" else f"{name}.{domain}"
        rows.append(
            tuple(
                str(value)
                for value in (
                    record.get("RecordId", ""),
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

    if result["operation"] == "domains_listed":
        _print_domains(result["domains"])
    elif result["operation"] in {"fetched", "listed"}:
        _print_records(result["domain"], result["records"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
