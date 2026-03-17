"""Tests for ubice.agent.scheduler."""
import io
from ubice.agent.scheduler import FOSSologyScheduler


def test_item_ok_close():
    processed = []

    def handler(upload_pk):
        processed.append(upload_pk)
        return {"status": "ok"}

    stream = io.StringIO("ITEM 42\nITEM 99\nCLOSE\n")
    sched = FOSSologyScheduler(handler)

    import io as _io
    import sys
    buf = _io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        sched.run(stream)
    finally:
        sys.stdout = old_stdout

    output = buf.getvalue()
    assert "OK 42" in output
    assert "OK 99" in output
    assert processed == [42, 99]


def test_empty_stream():
    sched = FOSSologyScheduler(lambda pk: {})
    stream = io.StringIO("")
    # Should not raise
    sched.run(stream)


def test_close_immediately():
    called = []
    sched = FOSSologyScheduler(lambda pk: called.append(pk))
    stream = io.StringIO("CLOSE\n")
    sched.run(stream)
    assert called == []
