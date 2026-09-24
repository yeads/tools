#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Create, update, query, list, or delete Alibaba Cloud DNS records."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import os
import sys
import time
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote

import requests


__version__ = "2.0.0"
ENDPOINT = "https://alidns.aliyuncs.com/"
VERSION = "2015-01-09"


class AliDNSError(RuntimeError):
    """A network transport or Alibaba Cloud DNS service error."""

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.request_id = request_id


def _percent_encode(value: Any) -> str:
    """Apply RFC 3986 percent-encoding for Alibaba Cloud RPC signatures."""
    return quote(str(value), safe="~")


def make_signature(secret: str, method: str, parameters: Mapping[str, Any]) -> str:
    """Build an Alibaba Cloud RPC API v1 signature."""
    canonical_query = "&".join(
        f"{_percent_encode(key)}={_percent_encode(parameters[key])}"
        for key in sorted(parameters)
    )
    string_to_sign = (
        f"{method.upper()}&{_percent_encode('/')}&{_percent_encode(canonical_query)}"
    )
    digest = hmac.new(
        (secret + "&").encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


@dataclass
class AliDNSClient:
    access_key_id: str
    access_key_secret: str
    security_token: Optional[str] = None
    timeout: float = 15.0
    requester: Callable[..., requests.Response] = requests.post
    clock: Callable[[], float] = time.time
    nonce_factory: Callable[[], Any] = uuid.uuid4

    def call(self, action: str, parameters: Mapping[str, Any]) -> Dict[str, Any]:
        timestamp = dt.datetime.fromtimestamp(
            self.clock(), tz=dt.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        request_parameters: Dict[str, Any] = {
            "AccessKeyId": self.access_key_id,
            "Action": action,
            "Format": "JSON",
            "SignatureMethod": "HMAC-SHA1",
            "SignatureNonce": str(self.nonce_factory()),
            "SignatureVersion": "1.0",
            "Timestamp": timestamp,
            "Version": VERSION,
        }
        if self.security_token:
            request_parameters["SecurityToken"] = self.security_token
        request_parameters.update(
            {key: value for key, value in parameters.items() if value is not None}
        )
        request_parameters["Signature"] = make_signature(
            self.access_key_secret, "POST", request_parameters
        )
        body = "&".join(
            f"{_percent_encode(key)}={_percent_encode(value)}"
            for key, value in request_parameters.items()
        )
        try:
            response = self.requester(
                ENDPOINT,
                data=body.encode("ascii"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise AliDNSError(f"Unable to connect to Alibaba Cloud DNS: {exc}") from exc

        try:
            result = response.json()
        except ValueError as exc:
            detail = response.text.strip() or response.reason
            if response.status_code >= 400:
                raise AliDNSError(f"HTTP {response.status_code}: {detail}") from exc
            raise AliDNSError("Alibaba Cloud DNS returned an unreadable response") from exc
        if not isinstance(result, dict):
            raise AliDNSError("Alibaba Cloud DNS returned an invalid response format")
        if response.status_code >= 400 or result.get("Code"):
            raise AliDNSError(
                str(result.get("Message") or f"HTTP {response.status_code}"),
                str(result["Code"]) if result.get("Code") else None,
                str(result["RequestId"]) if result.get("RequestId") else None,
            )
        return result

    def list_domains(self) -> List[Dict[str, Any]]:
        domains: List[Dict[str, Any]] = []
        page = 1
        while True:
            response = self.call(
                "DescribeDomains", {"PageNumber": page, "PageSize": 100}
            )
            batch = response.get("Domains", {}).get("Domain", [])
            if not isinstance(batch, list):
                raise AliDNSError("Alibaba Cloud DNS returned an invalid domain list")
            domains.extend(item for item in batch if isinstance(item, dict))
            total = _integer(response.get("TotalCount"), len(domains))
            if not batch or len(domains) >= total:
                return domains
            page += 1

    def list_all_records(self, domain: str) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        page = 1
        while True:
            response = self.call(
                "DescribeDomainRecords",
                {"DomainName": domain, "PageNumber": page, "PageSize": 500},
            )
            batch = response.get("DomainRecords", {}).get("Record", [])
            if not isinstance(batch, list):
                raise AliDNSError("Alibaba Cloud DNS returned an invalid record list")
            records.extend(item for item in batch if isinstance(item, dict))
            total = _integer(response.get("TotalCount"), len(records))
            if not batch or len(records) >= total:
                return records
            page += 1

    def list_records(
        self, domain: str, rr: str, record_type: str, line: str
    ) -> List[Dict[str, Any]]:
        # DescribeDomainRecords keyword filters are fuzzy; match exactly client-side.
        records: List[Dict[str, Any]] = []
        page = 1
        while True:
            response = self.call(
                "DescribeDomainRecords",
                {
                    "DomainName": domain,
                    "PageNumber": page,
                    "PageSize": 500,
                    "RRKeyWord": rr,
                    "TypeKeyWord": record_type,
                },
            )
            batch = response.get("DomainRecords", {}).get("Record", [])
            if not isinstance(batch, list):
                raise AliDNSError("Alibaba Cloud DNS returned an invalid record list")
            records.extend(
                item
                for item in batch
                if isinstance(item, dict)
                and str(item.get("RR", "")) == rr
                and str(item.get("Type", "")).upper() == record_type.upper()
                and str(item.get("Line", "")) == line
            )
            total = _integer(response.get("TotalCount"), len(batch))
            page_size = _integer(response.get("PageSize"), 500)
            if not batch or page * page_size >= total:
                return records
            page += 1

    def resolve_hostname(self, hostname: str) -> Tuple[str, str]:
        hostname_lower = hostname.lower()
        matches = []
        for item in self.list_domains():
            name = item.get("DomainName")
            if not isinstance(name, str):
                continue
            zone = name.strip().rstrip(".").lower()
            if hostname_lower == zone or hostname_lower.endswith("." + zone):
                matches.append(zone)
        if not matches:
            raise AliDNSError(f"No domain containing {hostname} was found in the account")
        domain = max(matches, key=len)
        rr = "@" if hostname_lower == domain else hostname[: -(len(domain) + 1)]
        return domain, rr

    def add_record(self, parameters: Mapping[str, Any]) -> Dict[str, Any]:
        return self.call("AddDomainRecord", parameters)

    def get_record(self, record_id: str) -> Dict[str, Any]:
        return self.call("DescribeDomainRecordInfo", {"RecordId": record_id})

    def update_record(self, parameters: Mapping[str, Any]) -> Dict[str, Any]:
        return self.call("UpdateDomainRecord", parameters)

    def delete_record(self, record_id: str) -> Dict[str, Any]:
        return self.call("DeleteDomainRecord", {"RecordId": record_id})


def _integer(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _selector_options(parser: argparse.ArgumentParser, update: bool = False) -> None:
    parser.add_argument(
        "--type",
        dest="record_type",
        default=None if update else "A",
        help="Record type, such as A, AAAA, CNAME, TXT, or MX "
        + ("(unchanged when omitted)" if update else "(default: A)"),
    )
    parser.add_argument(
        "--line", default=None if update else "default",
        help="DNS route code "
        + ("(unchanged when omitted)" if update else "(default: default)"),
    )
    parser.add_argument("--line-id", help="DNS route code; takes precedence over --line")


def _record_options(parser: argparse.ArgumentParser, update: bool = False) -> None:
    _selector_options(parser, update=update)
    parser.add_argument(
        "--ttl", type=int, default=None if update else 600,
        help="TTL from 1 to 604800 "
        + ("(unchanged when omitted)" if update else "(default: 600)"),
    )
    parser.add_argument(
        "--mx", type=int, default=None if update else 0,
        help="MX priority from 1 to 50"
        + (" (unchanged when omitted)" if update else ""),
    )
    parser.add_argument(
        "--weight", type=int, default=None, help="DNS load-balancing weight from 1 to 100"
    )
    parser.add_argument(
        "--status",
        choices=("ENABLE", "DISABLE"),
        default=None,
        help="Record status; unchanged when omitted, enabled for new records",
    )
    parser.add_argument("--remark", default=None, help="Record remark; unchanged when omitted")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alidns.py",
        description="Create, update, query, list, or delete Alibaba Cloud DNS records",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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
    set_command.add_argument("record_id", metavar="id", help="Record ID from ls")
    set_command.add_argument("value", help="Record value, such as 192.0.2.1")

    delete = commands.add_parser(
        "delete", aliases=("del", "rm"), help="Delete records by ID (aliases: del, rm)"
    )
    delete.add_argument("record_ids", metavar="id", nargs="+", help="Record IDs from ls")

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
    if hasattr(args, "record_id"):
        args.record_id = args.record_id.strip()
        if not args.record_id:
            parser.error("record ID cannot be empty")
    if hasattr(args, "record_ids"):
        args.record_ids = [record_id.strip() for record_id in args.record_ids]
        if not all(args.record_ids):
            parser.error("record IDs cannot be empty")
    if hasattr(args, "record_type"):
        if args.record_type is not None:
            args.record_type = args.record_type.strip().upper()
        args.line = args.line_id if args.line_id is not None else args.line
        if args.line is not None:
            args.line = args.line.strip()
        if args.record_type == "":
            parser.error("--type cannot be empty")
        if args.line == "":
            parser.error("--line/--line-id cannot be empty")
    try:
        _validate_record_values(args)
    except AliDNSError as exc:
        parser.error(str(exc))
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")


def _validate_record_values(args: argparse.Namespace) -> None:
    if getattr(args, "ttl", None) is not None and not 1 <= args.ttl <= 604800:
        raise AliDNSError("--ttl must be between 1 and 604800")
    if hasattr(args, "mx"):
        if args.mx is not None and args.mx != 0 and not 1 <= args.mx <= 50:
            raise AliDNSError("--mx must be between 1 and 50")
        if args.record_type == "MX" and args.mx == 0:
            raise AliDNSError("MX records require --mx with a priority from 1 to 50")
        if args.record_type not in {None, "MX"} and args.mx not in {None, 0}:
            raise AliDNSError("--mx applies only to MX records")
    if hasattr(args, "weight") and args.weight is not None:
        if not 1 <= args.weight <= 100:
            raise AliDNSError("--weight must be between 1 and 100")
        if args.record_type not in {None, "A", "AAAA"}:
            raise AliDNSError("--weight applies only to A or AAAA records")


def _record_parameters(
    args: argparse.Namespace, record_id: Optional[str] = None
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "RR": args.rr,
        "Type": args.record_type,
        "Value": args.value,
        "TTL": args.ttl,
        "Line": args.line,
    }
    if record_id is None:
        result["DomainName"] = args.domain
    else:
        result["RecordId"] = record_id
    if args.record_type == "MX":
        result["Priority"] = args.mx
    return result


def _apply_record_extras(
    client: AliDNSClient, args: argparse.Namespace, record_id: str
) -> None:
    if args.status is not None:
        client.call(
            "SetDomainRecordStatus",
            {"RecordId": record_id, "Status": args.status.title()},
        )
    if args.remark is not None:
        client.call(
            "UpdateDomainRecordRemark",
            {"RecordId": record_id, "Remark": args.remark},
        )
    if args.weight is not None:
        client.call(
            "SetDNSSLBStatus",
            {
                "SubDomain": args.domain if args.rr == "@" else f"{args.rr}.{args.domain}",
                "DomainName": args.domain,
                "Type": args.record_type,
                "Line": args.line,
                "Open": "true",
            },
        )
        client.call(
            "UpdateDNSSLBWeight", {"RecordId": record_id, "Weight": args.weight}
        )


def execute(client: AliDNSClient, args: argparse.Namespace) -> Dict[str, Any]:
    if args.command in {"ls", "show"}:
        if args.domain is None:
            return {"operation": "domains_listed", "domains": client.list_domains()}
        return {
            "operation": "listed",
            "domain": args.domain,
            "records": client.list_all_records(args.domain),
        }

    if args.command in {"delete", "del", "rm"}:
        deleted = []
        for record_id in dict.fromkeys(args.record_ids):
            try:
                client.delete_record(record_id)
            except AliDNSError as exc:
                detail = f"Unable to delete record {record_id}: {exc}"
                if deleted:
                    detail += f"; already deleted: {', '.join(deleted)}"
                raise AliDNSError(detail, exc.code, exc.request_id) from exc
            deleted.append(record_id)
        return {"operation": "deleted", "record_ids": deleted}

    if args.command == "set":
        record = client.get_record(args.record_id)
        for field in ("DomainName", "RR", "Type", "TTL", "Line"):
            if record.get(field) is None or str(record[field]) == "":
                raise AliDNSError(f"The record response has no valid {field}")
        args.domain, args.rr = record["DomainName"], record["RR"]
        for option, field in (("record_type", "Type"), ("line", "Line"), ("ttl", "TTL")):
            if getattr(args, option) is None:
                setattr(args, option, record[field])
        if args.mx is None:
            args.mx = _integer(record.get("Priority"), 0) if args.record_type == "MX" else 0
        _validate_record_values(args)
        response = client.update_record(_record_parameters(args, args.record_id))
        _apply_record_extras(client, args, args.record_id)
        return {
            "operation": "modified",
            "record_id": args.record_id,
            "request_id": response.get("RequestId"),
        }

    args.domain, args.rr = client.resolve_hostname(args.hostname)
    if args.command == "get":
        return {
            "operation": "fetched",
            "domain": args.domain,
            "records": client.list_records(
                args.domain, args.rr, args.record_type, args.line
            ),
        }

    response = client.add_record(_record_parameters(args))
    returned_id = response.get("RecordId")
    if returned_id is None or not str(returned_id):
        raise AliDNSError("The record was added, but the response has no RecordId")
    record_id = str(returned_id)
    _apply_record_extras(client, args, record_id)
    return {
        "operation": "created",
        "record_id": record_id,
        "request_id": response.get("RequestId"),
    }


def _display_width(value: str) -> int:
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
        print(domain.get("DomainName", ""))


def _print_records(domain: str, records: Sequence[Mapping[str, Any]]) -> None:
    rows = [("ID", "TYPE", "NAME", "VALUE", "LINE", "TTL", "STATUS")]
    for record in records:
        rr = str(record.get("RR", ""))
        hostname = domain if rr == "@" else f"{rr}.{domain}"
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


def _credential(*names: str) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate(parser, args)
    access_key_id = _credential(
        "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIYUN_ACCESS_KEY_ID"
    )
    access_key_secret = _credential(
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALIYUN_ACCESS_KEY_SECRET"
    )
    if not access_key_id or not access_key_secret:
        parser.error(
            "Set the ALIBABA_CLOUD_ACCESS_KEY_ID and "
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET environment variables"
        )
    client = AliDNSClient(
        access_key_id,
        access_key_secret,
        security_token=_credential(
            "ALIBABA_CLOUD_SECURITY_TOKEN", "ALIYUN_SECURITY_TOKEN"
        ),
        timeout=args.timeout,
    )
    try:
        result = execute(client, args)
    except AliDNSError as exc:
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
