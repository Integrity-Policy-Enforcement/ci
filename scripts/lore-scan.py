#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Find new IPE-related patch series on lore and dispatch the tests for them.

Each series is tracked by one GitHub issue keyed by the Message-ID of its
entry message (the cover letter, or patch 1/N, or a single patch). A series
whose issue already exists is skipped, so every series, and every new version
of a series, is tested once.
"""

import argparse
import email.message
import email.policy
import email.utils
import gzip
import json
import mailbox
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

LORE = "https://lore.kernel.org"
LIST = "linux-security-module"
LABEL = "lore-series"
MARKER = "lore-message-id"

# A series is relevant when one of its patches touches one of these paths ...
WATCHED_PATHS = (
    "security/ipe/",
    "fs/verity/",
    "include/linux/fsverity.h",
    "include/uapi/linux/fsverity.h",
    "drivers/md/dm-verity",
    "security/security.c",
    "include/linux/lsm_hook_defs.h",
    "Documentation/admin-guide/LSM/ipe.rst",
    "Documentation/security/ipe.rst",
)
# ... or when its subject or body mentions IPE.
MENTION = re.compile(r"\bIPE\b", re.IGNORECASE)

PATCH_SUBJECT = re.compile(r"^\s*\[(?P<tags>[^\]]*\bPATCH\b[^\]]*)\]\s*(?P<title>.*)$", re.I)
REPLY_SUBJECT = re.compile(r"^\s*(re|aw|sv|fwd?)\s*:", re.I)
VERSION = re.compile(r"\bv(\d+)\b", re.I)
COUNTER = re.compile(r"\b(\d+)/(\d+)\b")
DIFF_PATH = re.compile(r"^(?:diff --git a/(\S+) b/(\S+)|(?:---|\+\+\+) [ab]/(\S+))", re.M)
MESSAGE_ID = re.compile(r"<([^<>\s]+)>")


@dataclass
class Message:
    message_id: str
    in_reply_to: str | None
    subject: str
    title: str
    sender: str
    date: float
    version: int
    index: int
    total: int
    paths: set[str]
    mentions_ipe: bool


@dataclass
class Series:
    entry: Message
    members: list[Message] = field(default_factory=list)

    @property
    def matched_paths(self) -> list[str]:
        return sorted(
            path
            for member in self.members
            for path in member.paths
            if path.startswith(WATCHED_PATHS)
        )

    @property
    def mentions_ipe(self) -> bool:
        return any(member.mentions_ipe for member in self.members)

    @property
    def relevant(self) -> bool:
        return bool(self.matched_paths) or self.mentions_ipe


def first_message_id(value: str | None) -> str | None:
    if not value:
        return None
    match = MESSAGE_ID.search(str(value))
    return match.group(1) if match else None


def body_text(message: email.message.EmailMessage) -> str:
    parts = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() not in ("text/plain", "text/x-patch", "text/x-diff"):
            continue
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            parts.append(payload.decode(charset, errors="replace"))
        except LookupError:
            parts.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(parts)


def parse(message: email.message.EmailMessage) -> Message | None:
    subject = " ".join(str(message.get("Subject", "")).split())
    if REPLY_SUBJECT.match(subject):
        return None
    match = PATCH_SUBJECT.match(subject)
    message_id = first_message_id(message.get("Message-ID"))
    if not match or not message_id:
        return None
    tags = match.group("tags")
    version = VERSION.search(tags)
    counter = COUNTER.search(tags)
    body = body_text(message)
    paths = {path for groups in DIFF_PATH.findall(body) for path in groups if path}
    try:
        date = email.utils.parsedate_to_datetime(str(message.get("Date"))).timestamp()
    except (TypeError, ValueError):
        date = 0.0
    sender = email.utils.parseaddr(str(message.get("From", "")))
    return Message(
        message_id=message_id,
        in_reply_to=first_message_id(message.get("In-Reply-To")),
        subject=subject,
        title=match.group("title"),
        sender=sender[0] or sender[1],
        date=date,
        version=int(version.group(1)) if version else 1,
        index=int(counter.group(1)) if counter else 1,
        total=int(counter.group(2)) if counter else 1,
        paths=paths,
        mentions_ipe=bool(MENTION.search(subject) or MENTION.search(body)),
    )


def entry_of(message: Message, messages: dict[str, Message]) -> Message:
    current = message
    while current.index > 0 and current.total > 1:
        parent = messages.get(current.in_reply_to or "")
        if (
            parent is None
            or parent.version != current.version
            or parent.total != current.total
            or parent.index >= current.index
        ):
            break
        current = parent
    return current


def group(messages: dict[str, Message]) -> list[Series]:
    series: dict[str, Series] = {}
    for message in messages.values():
        entry = entry_of(message, messages)
        series.setdefault(entry.message_id, Series(entry)).members.append(message)
    # A series whose cover letter and first patch are both outside the
    # search window was seen by an earlier scan.
    complete = [s for s in series.values() if s.entry.index <= 1]
    return sorted(complete, key=lambda s: s.entry.date)


def load_mbox(path: Path) -> dict[str, Message]:
    messages = {}
    box = mailbox.mbox(
        path,
        factory=lambda f: email.message_from_binary_file(f, policy=email.policy.default),
        create=False,
    )
    for raw in box:
        message = parse(raw)
        if message:
            messages[message.message_id] = message
    return messages


def search_lore(days: int, destination: Path) -> None:
    query = f"s:PATCH AND rt:{days}.days.ago.."
    url = f"{LORE}/{LIST}/?x=m&q={urllib.parse.quote_plus(query)}"
    print(f"query: {url}", flush=True)
    request = urllib.request.Request(
        url, data=b"x=m", headers={"User-Agent": "ipe-ci-lore-scan"}
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            destination.write_bytes(gzip.decompress(response.read()))
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        destination.write_bytes(b"")  # public-inbox answers 404 for no results


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, text=True, capture_output=True).stdout


def known_message_ids() -> set[str]:
    issues = json.loads(
        gh("issue", "list", "--label", LABEL, "--state", "all",
           "--limit", "1000", "--json", "body")
    )
    pattern = re.compile(rf"<!--\s*{MARKER}:\s*(\S+)\s*-->")
    return {m.group(1) for issue in issues for m in pattern.finditer(issue["body"] or "")}


def inline(text: str) -> str:
    return "`" + text.replace("`", "'") + "`"


def issue_body(series: Series) -> str:
    entry = series.entry
    link = f"{LORE}/r/{urllib.parse.quote(entry.message_id, safe='@+.-_')}"
    reasons = []
    if series.matched_paths:
        reasons.append("touches " + ", ".join(inline(p) for p in series.matched_paths))
    if series.mentions_ipe:
        reasons.append("mentions IPE")
    patches = sorted(series.members, key=lambda m: m.index)
    return "\n".join([
        f"Patch series posted to {LIST}, tested automatically by IPE CI.",
        "",
        f"- Subject: {inline(entry.subject)}",
        f"- From: {inline(entry.sender)}",
        f"- Message-ID: {inline(entry.message_id)}",
        f"- lore: {link}",
        f"- Selected because it {' and '.join(reasons)}",
        "",
        "Patches seen by the scan:",
        *[f"- {inline(m.subject)}" for m in patches],
        "",
        "Test results are posted below as comments.",
        "",
        f"<!-- {MARKER}: {entry.message_id} -->",
    ]) + "\n"


def dispatch(series: Series, ref: str, architectures: str) -> None:
    entry = series.entry
    gh("label", "create", LABEL, "--force", "--color", "1d76db",
       "--description", "Patch series picked up from lore by IPE CI")
    url = gh(
        "issue", "create", "--label", LABEL,
        "--title", f"[lore] {entry.subject}"[:250],
        "--body", issue_body(series),
    ).strip()
    issue = url.rstrip("/").rsplit("/", 1)[-1]
    gh(
        "workflow", "run", "tests.yml", "--ref", ref,
        "-f", f"lore_message_id={entry.message_id}",
        "-f", f"series_subject={entry.subject[:200]}",
        "-f", f"report_issue={issue}",
        "-f", f"architectures={architectures}",
        "-f", "use_base_commit=true",
    )
    print(f"dispatched tests for {entry.message_id} -> {url}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=3, help="search window")
    parser.add_argument("--max-series", type=int, default=3,
                        help="series dispatched per scan; the rest wait for the next scan")
    parser.add_argument("--settle-minutes", type=int, default=30,
                        help="wait this long after the last patch so the series is complete")
    parser.add_argument("--ref", default="main", help="ref to run tests.yml from")
    parser.add_argument("--architectures", default="x86_64", choices=("all", "x86_64"))
    parser.add_argument("--mbox", type=Path, help="read this mbox instead of querying lore")
    parser.add_argument("--no-dedup", action="store_true",
                        help="do not consult the existing issues (offline testing)")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would be dispatched without doing it")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as temporary:
        mbox = args.mbox
        if mbox is None:
            mbox = Path(temporary) / "search.mbox"
            search_lore(args.days, mbox)
        messages = load_mbox(mbox)

    all_series = group(messages)
    relevant = [s for s in all_series if s.relevant]
    known = set() if args.no_dedup else known_message_ids()
    new = [s for s in relevant if s.entry.message_id not in known]
    print(f"{len(messages)} patch messages, {len(all_series)} series, "
          f"{len(relevant)} relevant, {len(new)} new", flush=True)

    settled = time.time() - args.settle_minutes * 60
    started = 0
    for series in new:
        entry = series.entry
        if max(member.date for member in series.members) > settled:
            print(f"still arriving, waiting: {entry.message_id} {entry.subject}")
            continue
        started += 1
        if started > args.max_series:
            print(f"deferred to the next scan: {entry.message_id} {entry.subject}")
            continue
        if args.dry_run:
            print(f"would test: {entry.message_id} {entry.subject}")
            print(issue_body(series))
            continue
        dispatch(series, args.ref, args.architectures)
    return 0


if __name__ == "__main__":
    sys.exit(main())
