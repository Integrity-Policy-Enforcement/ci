# SPDX-License-Identifier: GPL-2.0-only

import json
from typing import TextIO
import os
import signal
import traceback

import cases
from model import Case
from assets import BASELINE_POLICY
import ipe
import runtime

CASE_TIMEOUT_SECONDS = 60


def clean(text: object) -> str:
    return " ".join(str(text).replace("\r", " ").replace("\n", " ").split())


def run_in_child(case: Case) -> dict:
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        signal.alarm(CASE_TIMEOUT_SECONDS)
        try:
            for step in case.collect:
                step()
            for step in case.setup:
                step()
            report = {"detail": ""}
            if case.trigger:
                observation = case.trigger()
                report = {"errno": observation.errno, "detail": observation.detail}
        except BaseException as failure:
            report = {"error": f"{type(failure).__name__}: {clean(failure)}"}
        os.write(write_fd, json.dumps(report).encode())
        os._exit(0)

    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as report:
        payload = report.read()
    _, status = os.waitpid(child, 0)
    if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGALRM:
        return {"error": f"case exceeded {CASE_TIMEOUT_SECONDS}s"}
    if not os.WIFEXITED(status):
        return {"error": f"child terminated abnormally: {status}"}
    if not payload:
        return {"error": "child produced no result"}
    return json.loads(payload)


def test(case: Case) -> tuple[str, str] | None:
    """Run one case and put back whatever it disturbed."""
    try:
        with case.scope():
            result = run_in_child(case)
            if "error" in result:
                return "error", result["error"]
            if case.trigger and result["errno"] != case.expect:
                detail = f": {result['detail']}" if result["detail"] else ""
                return "failure", f"expected errno {case.expect}, got {result['errno']}{detail}"
            if case.check:
                problem = case.check(result["detail"])
                if problem:
                    return "failure", problem
            return None
    except Exception as failure:
        traceback.print_exc()
        return "error", f"{type(failure).__name__}: {clean(failure)}"


def run(output: TextIO) -> int:
    def emit(line: str) -> None:
        output.write(line.replace("\n", " ").replace("\r", " ") + "\n")
        output.flush()

    batches = cases.build()
    planned = [case for batch in batches for case in batch.cases]
    emit("TAP version 13")
    emit(f"1..{len(planned)}")

    failures = 0
    number = 0
    with runtime.run.scope():
        ipe.load_baseline(BASELINE_POLICY)
        for batch in batches:
            try:
                with batch.scope():
                    for step in batch.setup:
                        step()
                    for case in batch.cases:
                        number += 1
                        outcome = test(case)

                        if outcome is None:
                            emit(f"ok {number} {case.id}")
                        else:
                            kind, message = outcome
                            failures += 1
                            prefix = "error " if kind == "error" else ""
                            emit(f"not ok {number} {case.id} # {prefix}{clean(message)}")
            except Exception as failure:
                traceback.print_exc()
                emit(f"Bail out! batch {batch.id} failed: {clean(failure)}")
                return 1

    return 1 if failures else 0
