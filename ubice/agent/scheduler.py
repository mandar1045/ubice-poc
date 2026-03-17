"""
ubice.agent.scheduler
~~~~~~~~~~~~~~~~~~~~~
Implements the FOSSology ITEM/OK/CLOSE scheduler protocol over stdin/stdout.
Every FOSSology agent (nomos, monk, ojo) uses this same protocol.
Reference: src/lib/c/libfossscheduler.h in the FOSSology repo.
"""
import sys
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)


class FOSSologyScheduler:
    """
    Wraps the FOSSology ITEM/OK/CLOSE stdin/stdout protocol.

    Usage::

        def process(upload_pk: int) -> dict:
            return {"status": "ok", "upload_pk": upload_pk}

        sched = FOSSologyScheduler(process)
        sched.run()
    """

    def __init__(self, handler: Callable[[int], Any], agent_name: str = "ubice"):
        self.handler = handler
        self.agent_name = agent_name

    def run(self, stream=None) -> None:
        """
        Enter the scheduler event loop.
        Reads from stdin (or *stream* for testing), writes OK / error to stdout.
        """
        stream = stream or sys.stdin
        logger.info("%s agent started, waiting for scheduler input", self.agent_name)
        print(f"[{self.agent_name}] agent started", flush=True)

        for raw in stream:
            token = raw.strip()
            if not token:
                continue

            if token == "CLOSE":
                logger.info("received CLOSE")
                print(f"[{self.agent_name}] received CLOSE, exiting cleanly", flush=True)
                break

            if token.startswith("ITEM"):
                parts = token.split()
                upload_pk = int(parts[1]) if len(parts) > 1 else -1
                logger.info("processing upload_pk=%d", upload_pk)
                print(f"[{self.agent_name}] processing upload_pk={upload_pk}", flush=True)

                try:
                    result = self.handler(upload_pk)
                    logger.info("upload_pk=%d → %s", upload_pk, result)
                    print(f"[{self.agent_name}] result: {result}", flush=True)
                    print(f"OK {upload_pk}", flush=True)
                except Exception as exc:  # noqa: BLE001
                    logger.exception("error processing upload_pk=%d", upload_pk)
                    print(f"FATAL {upload_pk}: {exc}", flush=True)

            elif token.startswith("VERBOSE"):
                pass  # scheduler debug verbosity request — ignore in PoC

            else:
                logger.warning("unknown scheduler token: %r", token)
                print(f"[{self.agent_name}] unknown token: {token!r}", flush=True)
