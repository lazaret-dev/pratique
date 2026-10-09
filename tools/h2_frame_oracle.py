#!/usr/bin/env python3
"""Prints frames as Python's hyperframe (6.x) writes them, in hex, for the fixtures in the tests of
src/http/h2/frame.rs:  python3 tools/h2_frame_oracle.py   (needs `pip install hyperframe`). Padding and priority
fields appear only with the PADDED and PRIORITY flags set, as below."""
from hyperframe.frame import (ContinuationFrame, DataFrame, GoAwayFrame, HeadersFrame, PingFrame,
                              PriorityFrame, PushPromiseFrame, RstStreamFrame, SettingsFrame, WindowUpdateFrame)

frames = {
    "data_end": DataFrame(1, data=b"hello", flags=["END_STREAM"]),
    "data_padded": DataFrame(3, data=b"abc", pad_length=4, flags=["PADDED"]),
    "headers_end": HeadersFrame(1, data=b"\x82", flags=["END_HEADERS", "END_STREAM"]),
    "headers_open": HeadersFrame(5, data=b"\x82\x84"),
    "headers_priority_padded": HeadersFrame(7, data=b"\x82", flags=["END_HEADERS", "PRIORITY", "PADDED"], depends_on=3, stream_weight=15, exclusive=True, pad_length=2),
    "priority": PriorityFrame(5, depends_on=1, stream_weight=7),
    "rst_cancel": RstStreamFrame(1, error_code=8),
    "settings": SettingsFrame(0, settings={1: 4096, 2: 0, 4: 1048576}),
    "settings_ack": SettingsFrame(0, flags=["ACK"]),
    "push_promise": PushPromiseFrame(1, promised_stream_id=2, data=b"\x82", flags=["END_HEADERS"]),
    "ping": PingFrame(0, opaque_data=b"12345678"),
    "ping_ack": PingFrame(0, opaque_data=b"12345678", flags=["ACK"]),
    "goaway": GoAwayFrame(0, last_stream_id=5, error_code=0, additional_data=b"bye"),
    "window_update": WindowUpdateFrame(1, window_increment=65535),
    "window_update_conn": WindowUpdateFrame(0, window_increment=2147483647),
    "continuation": ContinuationFrame(1, data=b"\x82", flags=["END_HEADERS"]),
}
for name, f in frames.items():
    print("%-24s %s" % (name, f.serialize().hex()))
