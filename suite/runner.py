# SPDX-License-Identifier: GPL-2.0-only

import json
import os
import signal
import traceback

import cases
from session import Session

CASE_TIMEOUT_SECONDS = 60


def clean(text):
    return " ".join(str(text).replace("\r", " ").replace("\n", " ").split())


def run_in_child(case):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        signal.alarm(CASE_TIMEOUT_SECONDS)
        try:
            for step in case.setup:
                step()
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


def evaluate(case):
    result = run_in_child(case)
    if "error" in result:
        return "error", result["error"]
    if result["errno"] != case.expect:
        detail = f": {result['detail']}" if result["detail"] else ""
        return "failure", f"expected errno {case.expect}, got {result['errno']}{detail}"
    if case.check:
        problem = case.check(result["detail"])
        if problem:
            return "failure", problem
    return None


def run(output):
    def emit(line):
        output.write(line.replace("\n", " ").replace("\r", " ") + "\n")
        output.flush()

    batches = cases.build()
    planned = [case for batch in batches for case in batch.cases]
    emit("TAP version 13")
    emit(f"1..{len(planned)}")

    try:
        session = Session()
    except Exception as failure:
        traceback.print_exc()
        emit(f"Bail out! setup failed: {type(failure).__name__}: {clean(failure)}")
        return 1

    failures = 0
    number = 0
    for batch in batches:
        try:
            for case in batch.cases:
                number += 1
                try:
                    outcome = evaluate(case)
                except Exception as failure:
                    traceback.print_exc()
                    outcome = "error", f"{type(failure).__name__}: {clean(failure)}"

                try:
                    session.reset()
                except Exception as failure:
                    traceback.print_exc()
                    emit(f"Bail out! reset after {case.id} failed: {clean(failure)}")
                    return 1

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
