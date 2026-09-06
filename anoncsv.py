#!/usr/bin/env python3
"""Anonymize sensitive values in CSV files without sending data anywhere."""

from __future__ import annotations

import argparse
import csv
import hashlib
from io import StringIO
import ipaddress
import json
import re
import secrets
import sys
from pathlib import Path
from typing import Callable, Iterable


EMAIL_RE = re.compile(r"^([^@,\s]+)@([^@,\s]+)$")
PHONE_RE = re.compile(r"^[+()\d][\d\s().-]{5,}$")
VERSION = "0.1.0"


def stable_token(value: str, salt: str, prefix: str = "value") -> str:
    """Return a repeatable, non-reversible token for the same input and salt."""
    digest = hashlib.sha256(f"{salt}\0{value}".encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def fake_email(value: str, salt: str) -> str:
    match = EMAIL_RE.match(value.strip())
    if not match:
        return stable_token(value, salt, "email")
    local, domain = match.groups()
    local_token = stable_token(local, salt, "user").replace("_", ".")
    domain_token = stable_token(domain.lower(), salt, "example").replace("_", "")[:12]
    return f"{local_token}@{domain_token}.invalid"


def fake_ip(value: str, salt: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return stable_token(value, salt, "ip")
    digest = hashlib.sha256(f"{salt}\0{address}".encode()).digest()
    if address.version == 4:
        return f"198.51.100.{digest[0] % 254 + 1}"
    return "2001:db8::" + digest.hex()[:8]


def fake_phone(value: str, salt: str) -> str:
    digits = re.sub(r"\D", "", value)
    if not digits:
        return stable_token(value, salt, "phone")
    token = hashlib.sha256(f"{salt}\0{digits}".encode()).hexdigest()
    length = max(7, min(len(digits), 15))
    generated = "".join(str(int(char, 16) % 10) for char in token[:length])
    return "+" + generated


def fake_name(value: str, salt: str) -> str:
    return stable_token(value, salt, "person").replace("_", " ")


def infer_kind(header: str, sample: Iterable[str]) -> str | None:
    """Infer a conservative strategy from the column name and non-empty values."""
    normalized = re.sub(r"[^a-z0-9]", "", header.lower())
    values = [item.strip() for item in sample if item.strip()]
    if any(word in normalized for word in ("email", "mail", "e-mail")):
        return "email"
    if any(word in normalized for word in ("phone", "mobile", "tel", "telefon")):
        return "phone"
    if any(word in normalized for word in ("ip", "ipaddress", "ipadr")):
        return "ip"
    if any(word in normalized for word in ("name", "jmeno", "firstname", "lastname")):
        return "name"
    if values and all(EMAIL_RE.match(value) for value in values):
        return "email"
    if values and all(PHONE_RE.match(value) for value in values):
        return "phone"
    if values and all(_is_ip(value) for value in values):
        return "ip"
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


TRANSFORMS: dict[str, Callable[[str, str], str]] = {
    "email": fake_email,
    "ip": fake_ip,
    "phone": fake_phone,
    "name": fake_name,
    "token": lambda value, salt: stable_token(value, salt),
}


def anonymize_rows(
    rows: list[dict[str, str]],
    field_kinds: dict[str, str],
    salt: str,
) -> list[dict[str, str]]:
    result = []
    for row in rows:
        updated = row.copy()
        for field, kind in field_kinds.items():
            if field in updated and updated[field] != "":
                updated[field] = TRANSFORMS[kind](updated[field], salt)
        result.append(updated)
    return result


def parse_mapping(values: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for value in values:
        try:
            field, kind = value.split("=", 1)
        except ValueError as exc:
            raise ValueError(f"Neplatné mapování '{value}', použijte sloupec=typ") from exc
        if not field or kind not in TRANSFORMS:
            supported = ", ".join(sorted(TRANSFORMS))
            raise ValueError(f"Typ musí být jeden z: {supported}")
        mapping[field] = kind
    return mapping


def process_file(
    input_path: Path,
    output_path: Path,
    explicit_mapping: dict[str, str],
    salt: str,
    delimiter: str,
) -> tuple[int, dict[str, str]]:
    with input_path.open("r", encoding="utf-8-sig", newline="") as source:
        result, count, field_kinds = anonymize_text(
            source.read(), explicit_mapping, salt, delimiter
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(result, encoding="utf-8", newline="")
    return count, field_kinds


def process_json_file(
    input_path: Path,
    output_path: Path,
    explicit_mapping: dict[str, str],
    salt: str,
) -> tuple[int, dict[str, str]]:
    """Anonymize a JSON array containing objects with scalar values."""
    with input_path.open("r", encoding="utf-8-sig") as source:
        data = json.load(source)
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise ValueError("JSON musí obsahovat seznam objektů")
    rows = [{str(key): "" if value is None else str(value) for key, value in row.items()} for row in data]
    fields = list(dict.fromkeys(key for row in rows for key in row))
    inferred = {
        field: infer_kind(field, (row.get(field, "") for row in rows))
        for field in fields
    }
    field_kinds = {field: kind for field, kind in inferred.items() if kind is not None}
    field_kinds.update(explicit_mapping)
    unknown = sorted(set(field_kinds) - set(fields))
    if unknown:
        raise ValueError(f"Sloupce nenalezeny v JSON: {', '.join(unknown)}")
    result = anonymize_rows(rows, field_kinds, salt)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(rows), field_kinds


def process_xlsx_file(
    input_path: Path,
    output_path: Path,
    explicit_mapping: dict[str, str],
    salt: str,
) -> tuple[int, dict[str, str]]:
    """Anonymize the first worksheet in an XLSX file using optional openpyxl."""
    try:
        from openpyxl import load_workbook
    except ImportError as exc:
        raise ValueError("Pro Excel nainstalujte volitelnou závislost: pip install 'anoncsv[excel]'") from exc
    workbook = load_workbook(input_path)
    worksheet = workbook.active
    headers = [str(cell.value) if cell.value is not None else "" for cell in worksheet[1]]
    if not headers or not any(headers):
        raise ValueError("Excel soubor nemá záhlaví")
    rows = [
        {header: "" if value is None else str(value) for header, value in zip(headers, row)}
        for row in worksheet.iter_rows(min_row=2, values_only=True)
    ]
    inferred = {
        field: infer_kind(field, (row.get(field, "") for row in rows))
        for field in headers
    }
    field_kinds = {field: kind for field, kind in inferred.items() if kind is not None}
    field_kinds.update(explicit_mapping)
    unknown = sorted(set(field_kinds) - set(headers))
    if unknown:
        raise ValueError(f"Sloupce nenalezeny v Excelu: {', '.join(unknown)}")
    for row_number, row in enumerate(anonymize_rows(rows, field_kinds, salt), start=2):
        for column_number, header in enumerate(headers, start=1):
            worksheet.cell(row=row_number, column=column_number).value = row.get(header, "")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(output_path)
    return len(rows), field_kinds


def anonymize_text(
    text: str,
    explicit_mapping: dict[str, str],
    salt: str,
    delimiter: str = ",",
) -> tuple[str, int, dict[str, str]]:
    """Anonymize CSV text and return output text, row count, and used strategies."""
    if len(delimiter) != 1:
        raise ValueError("Oddělovač musí být právě jeden znak")
    reader = csv.DictReader(StringIO(text), delimiter=delimiter)
    if not reader.fieldnames:
        raise ValueError("CSV soubor nemá záhlaví")
    rows = list(reader)
    inferred = {
        field: infer_kind(field, (row.get(field, "") for row in rows))
        for field in reader.fieldnames
    }
    field_kinds = {field: kind for field, kind in inferred.items() if kind is not None}
    field_kinds.update(explicit_mapping)
    unknown = sorted(set(field_kinds) - set(reader.fieldnames))
    if unknown:
        raise ValueError(f"Sloupce nenalezeny v CSV: {', '.join(unknown)}")
    target = StringIO(newline="")
    writer = csv.DictWriter(target, fieldnames=reader.fieldnames, delimiter=delimiter)
    writer.writeheader()
    writer.writerows(anonymize_rows(rows, field_kinds, salt))
    return target.getvalue(), len(rows), field_kinds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lokální a bezpečná anonymizace CSV dat."
    )
    parser.add_argument("input", type=Path, help="Vstupní CSV soubor")
    parser.add_argument("output", type=Path, help="Výstupní anonymizované CSV")
    parser.add_argument("--version", action="version", version=f"anoncsv {VERSION}")
    parser.add_argument(
        "--format",
        choices=("csv", "json", "xlsx"),
        help="Formát vstupu (výchozí: podle přípony, jinak CSV)",
    )
    parser.add_argument(
        "--map",
        action="append",
        default=[],
        metavar="SLOUPEC=TYP",
        help="Ruční typ sloupce: email, ip, phone, name nebo token; lze opakovat",
    )
    parser.add_argument(
        "--salt",
        help="Tajný řetězec pro konzistentní tokeny; implicitně se vygeneruje náhodný",
    )
    parser.add_argument(
        "--delimiter",
        default=",",
        help="Oddělovač CSV (výchozí: čárka)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not args.input.exists():
            raise ValueError(f"Vstupní soubor neexistuje: {args.input}")
        mapping = parse_mapping(args.map)
        salt = args.salt or secrets.token_hex(16)
        suffix = args.input.suffix.lower()
        input_format = args.format or ("json" if suffix == ".json" else "xlsx" if suffix == ".xlsx" else "csv")
        if input_format == "json":
            count, field_kinds = process_json_file(args.input, args.output, mapping, salt)
        elif input_format == "xlsx":
            count, field_kinds = process_xlsx_file(args.input, args.output, mapping, salt)
        else:
            count, field_kinds = process_file(
                args.input, args.output, mapping, salt, args.delimiter
            )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Anonymizováno řádků: {count}")
    print(f"Zpracované sloupce: {', '.join(f'{k} ({v})' for k, v in field_kinds.items()) or 'žádné'}")
    if not args.salt:
        print("Poznámka: bez --salt se při každém spuštění vytvoří nové tokeny.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
