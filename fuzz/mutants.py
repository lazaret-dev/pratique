"""Deliberate bugs for `mutate.py`, each of which a fuzz target has to notice.

MUTANTS maps a name to (file, text, replacement, target[, seconds]): `text` must be in the file exactly once. EQUIVALENT names
the ones that change nothing anybody can see, with the reason; they are expected to survive.

The QUIC ones are here: the layers that keep state, which the targets of `quic_state_targets.rs` check against models; and the
QPACK ones, for the targets of `h3_targets.rs`. A target written `test:FILTER` is not a fuzz target but the unit tests that
`cargo test --lib FILTER` runs: some of what QPACK has to do (refuse an instruction that makes no sense, read what only another
implementation writes) is checked there and by the fixture of ls-qpack's output, not by a fuzz target, which only has a model of
what our own encoder writes.
"""
Q = "src/quic/"
H3 = "src/http/h3/qpack.rs"
H3F = "src/http/h3/frame.rs"
H3C = "src/http/h3/connection.rs"
H3T = "src/http/h3_transport.rs"
HTTP = "src/http/mod.rs"

MUTANTS = {
    # --- streams -----------------------------------------------------------------------------------------------------------
    # the stream that waits for connection credit is not looked at again when its lost data needs none
    "streams_unpark": (Q + "streams.rs", "if s.parked && !matches!(what, Gate::ConnBlocked) {", "if false && s.parked && !matches!(what, Gate::ConnBlocked) {", "quic_streams"),
    # a connection limit that is raised does not wake the streams that wait for it
    "streams_maxdata_wake": (Q + "streams.rs", "                        self.schedule(id);\n                    }\n                }\n                Ok(())\n            }\n            Frame::MaxStreamData", "                    }\n                }\n                Ok(())\n            }\n            Frame::MaxStreamData", "quic_streams"),
    # a lost MAX_DATA is not sent again
    "streams_lost_maxdata": (Q + "streams.rs", "                if v == self.recv_limit {\n                    self.max_data_pending = true;\n                }", "                let _ = v;", "quic_streams"),
    # --- the send buffer ---------------------------------------------------------------------------------------------------
    # an acknowledgment of what is forgotten already is not clipped
    "sendbuf_ack_clip": (Q + "sendbuf.rs", "let r = offset.max(self.base)..offset + len as u64 + u64::from(fin);", "let r = offset..offset + len as u64 + u64::from(fin);", "quic_buffers"),
    # a report of loss for what was never sent is believed
    "sendbuf_lost_unclipped": (Q + "sendbuf.rs", "let r = offset.max(self.base)..(offset + len as u64 + u64::from(fin)).min(self.next);", "let r = offset.max(self.base)..(offset + len as u64 + u64::from(fin));", "quic_buffers"),
    # new data goes past the flow control limit
    "sendbuf_limit": (Q + "sendbuf.rs", "let room = written.min(limit).saturating_sub(offset);", "let room = written.saturating_sub(offset);", "quic_buffers"),
    # --- sets of ranges ----------------------------------------------------------------------------------------------------
    # two ranges that touch are not joined
    "rangeset_touching": (Q + "rangeset.rs", "            if e >= start {\n                start = s;", "            if e > start {\n                start = s;", "quic_buffers"),
    # the end of a range that is cut in the middle is lost
    "rangeset_remove_tail": (Q + "rangeset.rs", "            if e > r.end {\n                self.ranges.insert(r.end, e);", "            if e > r.end + 1 {\n                self.ranges.insert(r.end, e);", "quic_buffers"),
    # a pop takes one number too many
    "rangeset_pop_max": (Q + "rangeset.rs", "let end = e.min(s.saturating_add(max));", "let end = e.min(s.saturating_add(max + 1));", "quic_buffers"),
    # --- the receive buffer ------------------------------------------------------------------------------------------------
    # two copies of the same bytes that differ are not noticed
    "reassembly_inconsistent": (Q + "reassembly.rs", "if have[from..from + overlap] != data[..overlap] {", "if false {", "quic_buffers"),
    # data one byte beyond the window is taken
    "reassembly_window": (Q + "reassembly.rs", "if end > self.read.saturating_add(window) {", "if end > self.read.saturating_add(window) + 1 {", "quic_buffers"),
    # --- transport parameters ----------------------------------------------------------------------------------------------
    "params_payload_size": (Q + "transport_params.rs", "if p.max_udp_payload_size < MIN_UDP_PAYLOAD_SIZE {", "if p.max_udp_payload_size < 1000 {", "quic_params"),
    "params_duplicates": (Q + "transport_params.rs", "if ids.windows(2).any(|w| w[0] == w[1]) {", "if false {", "quic_params"),
    # the limit is one too high (the target has seeds on both sides of every limit)
    "params_ack_delay": (Q + "transport_params.rs", "if p.max_ack_delay >= MAX_ACK_DELAY_LIMIT {", "if p.max_ack_delay > MAX_ACK_DELAY_LIMIT {", "quic_params"),
    # --- loss recovery -----------------------------------------------------------------------------------------------------
    # the packet threshold is off by one
    "recovery_packet_threshold": (Q + "recovery.rs", "largest >= pn + PACKET_THRESHOLD", "largest > pn + PACKET_THRESHOLD", "quic_recovery"),
    # a packet is declared lost by the time threshold too late
    "recovery_time_threshold": (Q + "recovery.rs", "if now.saturating_duration_since(p.time) >= loss_delay ||", "if now.saturating_duration_since(p.time) > loss_delay * 2 ||", "quic_recovery"),
    # a packet that is sent is not counted as in flight
    "recovery_in_flight": (Q + "recovery.rs", "            sp.sent.insert(sent.pn, sent);\n            self.cc.on_sent(size);", "            sp.sent.insert(sent.pn, sent);", "quic_recovery"),
    # the timer is cleared when it should be set
    "recovery_timer": (Q + "recovery.rs", "        if !self.any_ack_eliciting_in_flight() && self.peer_completed_address_validation() {\n            self.timer = None;", "        if !self.any_ack_eliciting_in_flight() || self.peer_completed_address_validation() {\n            self.timer = None;", "quic_recovery"),
    # --- the connection (the whole of it is needed to see these) -----------------------------------------------------------
    # stream data that was lost is not sent again
    "connection_stream_lost": (Q + "connection.rs", "SentFrame::Stream(sf) => self.streams.on_lost(sf),", "SentFrame::Stream(_) => {}", "quic_connection", 40),
    # the streams are never told that their data was acknowledged: nothing is freed and no stream is ever forgotten
    "connection_stream_acked_never": (Q + "connection.rs", "SentFrame::Stream(sf) => self.streams.on_acked(sf),", "SentFrame::Stream(_) => {}", "quic_connection", 60),
    # what arrives does not count as activity, so a connection that only listens idles out
    "connection_idle_on_receive": (Q + "connection.rs", "        self.last_activity = now;\n        self.eliciting_sent_since_rx = false;", "        self.eliciting_sent_since_rx = false;", "quic_connection", 60),
    # --- QPACK -------------------------------------------------------------------------------------------------------------
    # the decoder unwraps the Required Insert Count wrongly at the edge
    "h3_ric_unwrap": (H3, "        if required > max_value {\n            if required <= full_range {", "        if required >= max_value {\n            if required <= full_range {", "test:h3::qpack::tests::a_section_may_wait"),
    # the encoder writes the Required Insert Count one too high
    "h3_ric_encode": (H3, "required % (2 * (self.peer_max_capacity / ENTRY_OVERHEAD) as u64) + 1", "required % (2 * (self.peer_max_capacity / ENTRY_OVERHEAD) as u64) + 2", "h3_qpack_exchange"),
    # the encoder evicts an entry that a section not acknowledged refers to
    "h3_evict_referenced": (H3, "if self.table.dropped + (evicted as u64) >= self.known_received || e.refs > 0 {", "if self.table.dropped + (evicted as u64) >= self.known_received {", "h3_qpack_exchange"),
    # the encoder evicts an entry that the decoder has not acknowledged
    "h3_evict_unacknowledged": (H3, "if self.table.dropped + (evicted as u64) >= self.known_received || e.refs > 0 {", "if e.refs > 0 {", "h3_qpack_exchange"),
    # the encoder lets one stream more be blocked than it may
    "h3_blocked_encoder": (H3, "already || self.blocked_count() < allowed", "already || self.blocked_count() <= allowed", "h3_qpack_exchange"),
    # the decoder lets one stream more wait than it said it would
    "h3_blocked_decoder": (H3, "if !self.blocked.contains_key(&stream) && self.blocked.len() >= self.max_blocked {", "if !self.blocked.contains_key(&stream) && self.blocked.len() > self.max_blocked {", "h3_qpack"),
    # a stream that has what it waited for is still counted as blocked until it is tried again
    "h3_blocked_stale": (H3, "        self.blocked.retain(|_, required| *required > inserted);\n", "        let _ = inserted;\n", "h3_qpack_exchange"),
    # a section that is acknowledged does not free the entries it referred to
    "h3_release_noop": (H3, "e.refs = e.refs.saturating_sub(1);", "let _ = e;", "h3_qpack_exchange"),
    # a stream that is cancelled does not free the entries its sections referred to
    "h3_cancel_forgets": (H3, "                    for s in &q {\n                        self.release(s);\n                    }", "                    let _ = q;", "h3_qpack_exchange"),
    # an acknowledgment is taken for the newest section of its stream, not the oldest
    "h3_ack_newest": (H3, "q.pop_front()).ok_or(Error::DecoderStream", "q.pop_back()).ok_or(Error::DecoderStream", "h3_qpack_exchange"),
    # the decoder does not acknowledge the sections it decodes
    "h3_no_section_ack": (H3, "        if required > 0 {\n            // the encoder counts on being told", "        if false {\n            // the encoder counts on being told", "h3_qpack_exchange"),
    # the decoder does not say how many entries it has beyond what its acknowledgments said
    "h3_no_increment": (H3, "        if inserted > self.known_received {\n            put_int(&mut self.out, 6, 0x00,", "        if false {\n            put_int(&mut self.out, 6, 0x00,", "h3_qpack_exchange"),
    # an acknowledgment does not tell the encoder what the decoder has
    "h3_ack_known": (H3, "                self.known_received = self.known_received.max(section.required);", "                let _ = section.required;", "h3_qpack_exchange"),
    # the table evicts the newest entry, not the oldest
    "h3_evict_newest": (H3, "if let Some(old) = self.entries.pop_front() {", "if let Some(old) = self.entries.pop_back() {", "h3_qpack_exchange"),
    # a smaller capacity evicts one entry, not as many as it takes
    "h3_shrink_one": (H3, "        while self.size > capacity {\n            self.evict_oldest();\n        }", "        if self.size > capacity {\n            self.evict_oldest();\n        }", "h3_qpack"),
    # a negative base is one too high
    "h3_base_negative": (H3, "            required - delta - 1\n", "            required - delta\n", "h3_qpack_exchange"),
    # a post-base index is one too high
    "h3_post_base": (H3, "let abs = base.checked_add(index).ok_or(Error::Decompression(\"a reference that does not fit\"))?;", "let abs = base.checked_add(index + 1).ok_or(Error::Decompression(\"a reference that does not fit\"))?;", "h3_qpack_exchange"),
    # an integer's continuation bytes count 6 bits, not 7
    "h3_int_shift": (H3, "        shift += 7;\n    }\n}", "        shift += 6;\n    }\n}", "h3_qpack_exchange"),
    # the decoder lets a list through at twice the limit
    "h3_list_limit": (H3, "            if list > limit {\n                within = false;", "            if list > limit * 2 {\n                within = false;", "h3_qpack"),
    # --- QPACK, by the unit tests ------------------------------------------------------------------------------------------
    # a reference at the required insert count is let through
    "h3_ref_at_required": (H3, "        if abs >= required {\n            return Err(Error::Decompression(\"a reference to an entry at or above", "        if abs > required {\n            return Err(Error::Decompression(\"a reference to an entry at or above", "test:h3::qpack"),
    # an Insert Count Increment of 0 is let through
    "h3_increment_zero": (H3, "                if n == 0 {\n                    return Err(Error::DecoderStream(\"an insert count increment of 0\"));", "                if false {\n                    return Err(Error::DecoderStream(\"an insert count increment of 0\"));", "test:h3::qpack"),
    # a Duplicate is read with a 4-bit index
    "h3_duplicate_prefix": (H3, "            // Duplicate\n            let index = get_int(buf, &mut pos, 5)?;", "            // Duplicate\n            let index = get_int(buf, &mut pos, 4)?;", "test:h3::qpack"),
    # a capacity equal to the maximum is refused
    "h3_capacity_max": (H3, "if capacity > self.max_capacity as u64 {", "if capacity >= self.max_capacity as u64 {", "test:h3::qpack"),
    # an Insert With Name Reference to the dynamic table counts from the oldest entry, not the newest
    "h3_name_ref_relative": (H3, "let abs = self.table.inserted().checked_sub(index).and_then(|n| n.checked_sub(1))", "let abs = self.table.dropped.checked_add(index)", "test:h3::qpack"),
    # --- HTTP/3 frames, by h3_frames ---------------------------------------------------------------------------------------
    # a frame that is skipped is skipped one byte short
    "h3_frame_skip": (H3F, "            _ => State::Skip(len),", "            _ => State::Skip(len.saturating_sub(1)),", "h3_frames"),
    # a DATA frame is read one byte too long
    "h3_frame_data_len": (H3F, "                    State::Data(len)\n", "                    State::Data(len + 1)\n", "h3_frames"),
    # a HEADERS frame of exactly the size allowed is refused
    "h3_frame_headers_limit": (H3F, "if len > self.max_headers as u64 {", "if len >= self.max_headers as u64 {", "h3_frames"),
    # a control frame of exactly the longest size kept is refused
    "h3_frame_whole_limit": (H3F, "if len > MAX_WHOLE {", "if len >= MAX_WHOLE {", "h3_frames"),
    # the control stream may begin with some of the other frames
    "h3_frame_first": (H3F, "if !self.started && t != ty::SETTINGS {", "if !self.started && t > ty::SETTINGS {", "h3_frames"),
    # a second SETTINGS frame is taken
    "h3_frame_second_settings": (H3F, "ty::SETTINGS if self.settings_seen =>", "ty::SETTINGS if false =>", "h3_frames"),
    # MAX_PUSH_ID is taken by a client
    "h3_frame_max_push_id": (H3F, "ty::MAX_PUSH_ID => return Err(FrameError::conn(code::H3_FRAME_UNEXPECTED, \"MAX_PUSH_ID sent to a client\")),", "ty::MAX_PUSH_ID => {}", "h3_frames"),
    # CONTINUATION's type is not known to be reserved
    "h3_frame_reserved_type": (H3F, "matches!(t, 0x02 | 0x06 | 0x08 | 0x09)", "matches!(t, 0x02 | 0x06 | 0x08)", "h3_frames"),
    # a push promise is a frame that should not be there, not a push that was not allowed
    "h3_frame_push_code": (H3F, "FrameError::conn(code::H3_ID_ERROR, \"a push promise", "FrameError::conn(code::H3_FRAME_UNEXPECTED, \"a push promise", "h3_frames"),
    # GOAWAY may hold more than the one integer
    "h3_frame_one_integer": (H3F, "if n != payload.len() {", "if n > payload.len() {", "h3_frames"),
    # an integer of 32 to 63 is read as one of two bytes
    "h3_frame_varint_len": (H3F, "let need = 1usize << (self.bytes[0] >> 6);", "let need = 1usize << (self.bytes[0] >> 5);", "h3_frames"),
    # a stream cut in the middle of a type is between frames
    "h3_frame_boundary": (H3F, "matches!(&self.state, State::Type(p) if p.have == 0)", "matches!(&self.state, State::Type(_))", "h3_frames"),
    # a field section has a byte changed
    "h3_frame_headers_bytes": (H3F, "buf.extend_from_slice(&input[pos..pos + n]);", "buf.extend_from_slice(&input[pos..pos + n]);\n                    if buf.len() > 2 {\n                        buf[2] ^= 1;\n                    }", "h3_frames"),
    # --- HTTP/3 connection, by the unit tests ------------------------------------------------------------------------------
    # a stream at exactly the id of a GOAWAY is taken as one the server took
    "h3_conn_goaway_ge": (H3C, "let lost: Vec<u64> = self.streams.keys().copied().filter(|&s| s >= id).collect();", "let lost: Vec<u64> = self.streams.keys().copied().filter(|&s| s > id).collect();", "test:h3::connection"),
    # a GOAWAY with the same id as the one before is refused
    "h3_conn_goaway_up": (H3C, "if self.goaway.is_some_and(|before| id > before) {", "if self.goaway.is_some_and(|before| id >= before) {", "test:h3::connection"),
    # a push stream is a stream creation error
    "h3_conn_push_code": (H3C, "self.fail(t, code::H3_ID_ERROR, \"a push stream, though push was not allowed\");", "self.fail(t, code::H3_STREAM_CREATION_ERROR, \"a push stream, though push was not allowed\");", "test:h3::connection"),
    # a stream that is not read is read all the same
    "h3_conn_no_stall": (H3C, "if s.unread() >= self.cfg.body_buffer {\n                s.stalled = true;", "if s.unread() >= usize::MAX {\n                s.stalled = true;", "test:h3::connection"),
    # a stream that was not read further is not read again when the application has taken some
    "h3_conn_stall_stays": (H3C, "if s.stalled && s.unread() < self.cfg.body_buffer {", "if false && s.stalled && s.unread() < self.cfg.body_buffer {", "test:h3::connection"),
    # a body of exactly the length the response says is refused
    "h3_conn_length_exact": (H3C, "s.expected.is_some_and(|n| s.received + bytes.len() as u64 > n)", "s.expected.is_some_and(|n| s.received + bytes.len() as u64 >= n)", "test:h3::connection"),
    # a body shorter than the response says is let through
    "h3_conn_length_short": (H3C, "if s.expected.is_some_and(|n| s.received != n) {\n            self.fail_stream(t, id, code::H3_MESSAGE_ERROR, \"less DATA", "if s.expected.is_some_and(|n| s.received > n) {\n            self.fail_stream(t, id, code::H3_MESSAGE_ERROR, \"less DATA", "test:h3::connection"),
    # a 304 has a body
    "h3_conn_bodiless_304": (H3C, "s.bodiless = s.head_request || status == 204 || status == 304;", "s.bodiless = s.head_request || status == 204;", "test:h3::connection"),
    # a 101 is let through
    "h3_conn_101": (H3C, "if status == 101 || s.interim > MAX_INTERIM {", "if s.interim > MAX_INTERIM {", "test:h3::connection"),
    # a section waits for one entry more than it needs
    "h3_conn_blocked_off_by_one": (H3C, "s.blocked.as_ref().is_some_and(|(_, need)| *need <= have)", "s.blocked.as_ref().is_some_and(|(_, need)| *need < have)", "test:h3::connection"),
    # the end of a stream that waited for the table is lost
    "h3_conn_held_fin": (H3C, "Held::Fin => self.apply(t, id, Item::Fin),", "Held::Fin => Flow::Continue,", "test:h3::connection"),
    # a stream given up does not tell the encoder
    "h3_conn_release_cancel": (H3C, "                let _ = t.stop_sending(id, code::H3_REQUEST_CANCELLED);\n                self.decoder.cancel_stream(id);", "                let _ = t.stop_sending(id, code::H3_REQUEST_CANCELLED);", "test:h3::connection"),
    # a stream that failed does not tell the encoder
    "h3_conn_fail_cancel": (H3C, "        // (what the encoder counted on from this stream is released)\n        self.decoder.cancel_stream(id);\n", "        // (what the encoder counted on from this stream is released)\n", "test:h3::connection"),
    # a critical stream may end
    "h3_conn_critical_fin": (H3C, "                        if fin {\n                            self.fail(t, code::H3_CLOSED_CRITICAL_STREAM, \"a stream the connection cannot do without was closed\");\n                            return;\n                        }", "                        if false && fin {\n                            self.fail(t, code::H3_CLOSED_CRITICAL_STREAM, \"a stream the connection cannot do without was closed\");\n                            return;\n                        }", "test:h3::connection"),
    # a request that cannot be opened for the server's limit is said to be unavailable
    "h3_conn_full": (H3C, "Err(TransportError::Blocked) => return Err(OpenError::Full),", "Err(TransportError::Blocked) => return Err(OpenError::Unavailable),", "test:h3::connection"),
    # a header list of exactly the size the server takes is refused
    "h3_conn_peer_limit": (H3C, "if size > limit {", "if size >= limit {", "test:h3::connection"),
    # every reset is a request that may be sent again
    "h3_conn_rejected": (H3C, "self.fail_stream(t, id, c, \"the server reset the stream\", c == code::H3_REQUEST_REJECTED);", "self.fail_stream(t, id, c, \"the server reset the stream\", true);", "test:h3::connection"),
    # the body a stream holds to write is not bounded
    "h3_conn_send_unbounded": (H3C, "let n = data.len().min(self.cfg.send_buffer.saturating_sub(s.out.pending()));", "let n = data.len();", "test:h3::connection"),
    # the end of a request is marked though not all of the body was taken
    "h3_conn_fin_partial": (H3C, "if end_stream && n == data.len() {\n            s.out.fin = true;", "if end_stream {\n            s.out.fin = true;", "test:h3::connection"),
    # a stream that is turned away is remembered for ever
    "h3_conn_ignored_leak": (H3C, "                    Ok((_, true)) | Err(_) => {\n                        self.ignored.remove(&id);\n                        return;\n                    }", "                    Ok((_, true)) | Err(_) => {\n                        return;\n                    }", "test:h3::connection"),
    # a stream of a type that is not known is read as one that is
    "h3_conn_unknown_type": (H3C, "                self.uni.remove(&id);\n                self.ignored.insert(id);", "                self.uni.remove(&id);", "test:h3::connection"),
}

# The same bugs of the connection again, for the fuzz target `h3_connection` to find: its model server and its checks (the books,
# the order of what the application sees, what a response says, what the client wrote read back) are broader than any one unit test.
for _name in ("h3_conn_blocked_off_by_one", "h3_conn_held_fin", "h3_conn_release_cancel", "h3_conn_fail_cancel", "h3_conn_send_unbounded",
              "h3_conn_fin_partial", "h3_conn_ignored_leak", "h3_conn_stall_stays", "h3_conn_no_stall"):
    _file, _old, _new, _ = MUTANTS[_name]
    MUTANTS[_name + "_fuzz"] = (_file, _old, _new, "h3_connection", 40)

MUTANTS.update({
    # --- equivalent ones ---------------------------------------------------------------------------------------------------
    "connection_stream_acked_twice": (Q + "connection.rs", "SentFrame::Stream(sf) => self.streams.on_acked(sf),", "SentFrame::Stream(sf) => { self.streams.on_acked(sf); self.streams.on_acked(sf) }", "quic_connection", 40),
    "connection_crypto_acked_never": (Q + "connection.rs", "SentFrame::Crypto { offset, len } => self.spaces[si].crypto_tx.on_acked(*offset, *len, false),", "SentFrame::Crypto { .. } => {}", "quic_connection", 40),
})

# What the transport asks to know whom to wake (`ready`, `writable`): a stream that is not woken for news it has waits for ever, so the model
# server's checks compare each with what the poll or the send then does.
MUTANTS.update({
    "h3_conn_ready_trailers": (H3C, "s.head.is_some() || s.unread() > 0 || s.failure.is_some() || s.trailers.is_some() || s.remote_ended,", "s.head.is_some() || s.unread() > 0 || s.failure.is_some() || s.remote_ended,", "h3_connection", 40),
    "h3_conn_ready_unread": (H3C, "s.head.is_some() || s.unread() > 0 || s.failure.is_some() || s.trailers.is_some() || s.remote_ended,", "s.head.is_some() || s.unread() > 1 || s.failure.is_some() || s.trailers.is_some() || s.remote_ended,", "h3_connection", 40),
    "h3_conn_ready_failure": (H3C, "s.head.is_some() || s.unread() > 0 || s.failure.is_some() || s.trailers.is_some() || s.remote_ended,", "s.head.is_some() || s.unread() > 0 || s.trailers.is_some() || s.remote_ended,", "h3_connection", 40),
    "h3_conn_ready_head": (H3C, "s.head.is_some() || s.unread() > 0 || s.failure.is_some() || s.trailers.is_some() || s.remote_ended,", "s.unread() > 0 || s.failure.is_some() || s.trailers.is_some() || s.remote_ended,", "h3_connection", 40),
    "h3_conn_writable_stopped": (H3C, "Some(s) => s.failure.is_some() || s.send_stopped.is_some() || s.out.fin || self.send_capacity(id) > 0,", "Some(s) => s.failure.is_some() || s.out.fin || self.send_capacity(id) > 0,", "h3_connection", 40),
    "h3_conn_writable_fin": (H3C, "Some(s) => s.failure.is_some() || s.send_stopped.is_some() || s.out.fin || self.send_capacity(id) > 0,", "Some(s) => s.failure.is_some() || s.send_stopped.is_some() || self.send_capacity(id) > 0,", "h3_connection", 40),
    "h3_conn_writable_failure": (H3C, "Some(s) => s.failure.is_some() || s.send_stopped.is_some() || s.out.fin || self.send_capacity(id) > 0,", "Some(s) => s.send_stopped.is_some() || s.out.fin || self.send_capacity(id) > 0,", "h3_connection", 40),
})

# The host rule of a client (`hostrules.rs`, `check_target` in `http/mod.rs`) and the limits on a URL (`UrlLimits` in `http/url.rs`): what they let
# through is what the caller's module may reach, so each way of letting through too much (or of not looking) is a bug the tests have to find.
HR = "src/http/hostrules.rs"
URLRS = "src/http/url.rs"
_ALLOWS = "if self.exact.iter().any(|(e, p)| e == host && p.map_or(!default_only || port == default_port, |p| port == p)) {"
MUTANTS.update({
    # the first URL is not looked at
    "hostrule_start_unchecked": (HTTP, "        self.check_target(&url, 0)?;\n        let method = method.to_ascii_uppercase();", "        let method = method.to_ascii_uppercase();", "test:http::egress_tests"),
    # a redirect is not looked at before it is followed
    "hostrule_follow_unchecked": (HTTP, "        self.check_target(&next, *hops)?;", "", "test:http::egress_tests"),
    # the rule is for the host the request was made to, not the one a redirect goes to
    "hostrule_follow_old_host": (HTTP, "        self.check_target(&next, *hops)?;", "        self.check_target(&hop.url, *hops)?;", "test:http::egress_tests"),
    # the limits on a URL are not applied to what a check of the target does
    "hostrule_target_limits": (HTTP, "        self.url_limits.check(url).map_err(|reason| Error::Refused(Refused { hop, by: RefusedBy::UrlLimit, reason }))?;\n", "", "test:http::egress_tests"),
    # the rule looks at the host and the scheme's port, not at the port the URL has
    "hostrule_target_port": (HTTP, "Some(rules) if !rules.allows_url(url) => Err(Error::Refused(Refused {", "Some(rules) if !rules.allows(&url.host, url.default_port(), url.default_port()) => Err(Error::Refused(Refused {", "test:http::egress_tests"),
    # the text the caller gave is not looked at before it is parsed
    "hostrule_text_first": (HTTP, "        self.check_text(url, 0)?;\n        let url = Url::parse(url)?;", "        let url = Url::parse(url)?;", "test:http::egress_tests"),
    # the text of a redirect's Location is not looked at as it came
    "hostrule_text_location": (HTTP, "        self.check_text(&location, *hops)?;\n", "", "test:http::egress_tests"),
    # the URL a redirect resolves to is not looked at as text (a short Location can make a long URL)
    "hostrule_text_resolved": (HTTP, "        self.check_text(&next.to_string(), *hops)?;\n", "", "test:http::egress_tests"),
    # the domain of a wildcard is allowed too
    "hostrule_wildcard_apex": (HR, "            None => false,\n        })", "            None => host == &s[1..],\n        })", "test:http::hostrules"),
    # what is before the suffix is not looked at when a wildcard has any depth (empty labels, a hyphen at the start)
    "hostrule_wildcard_sloppy": (HR, "                } else {\n                    is_name(before)\n                }", "                } else {\n                    true\n                }", "test:http::hostrules"),
    # a wildcard has no dot in its suffix: `*.example.com` allows `evilexample.com`
    "hostrule_wildcard_no_dot": (HR, "let suffix = format!(\".{domain}\");", "let suffix = domain.to_string();", "test:http::hostrules"),
    # a wildcard of one label (`*.com`) is accepted
    "hostrule_wildcard_one_label": (HR, "                if !domain.contains('.') {", "                if false && !domain.contains('.') {", "test:http::hostrules"),
    # a host that is allowed is allowed by prefix
    "hostrule_exact_prefix": (HR, _ALLOWS, _ALLOWS.replace("e == host", "host.starts_with(e.as_str())"), "test:http::hostrules"),
    # the comparison is case-sensitive for the host as given
    "hostrule_case": (HR, "        let lower = host.to_ascii_lowercase();\n        let host = lower.strip_suffix('.').unwrap_or(&lower);", "        let lower = host.to_string();\n        let host = lower.strip_suffix('.').unwrap_or(&lower);", "test:http::hostrules"),
    # one-label wildcards: the switch does nothing
    "hostrule_one_label_off": (HR, "                if self.one_label {", "                if false {", "test:http::hostrules"),
    # one-label wildcards: the label is only a name (dots, underscores)
    "hostrule_one_label_name": (HR, "                    is_strict_label(before)", "                    is_name(before)", "test:http::hostrules"),
    # a label of 64 bytes is let through
    "hostrule_label_length": (HR, "s.len() <= 63 && !s.starts_with('-')", "s.len() <= 64 && !s.starts_with('-')", "test:http::hostrules"),
    # a label that ends with a hyphen is let through
    "hostrule_label_hyphen": (HR, "!s.starts_with('-') && !s.ends_with('-') && s.bytes()", "!s.starts_with('-') && s.bytes()", "test:http::hostrules"),
    # default port only: a wildcard matches any port
    "hostrule_port_wildcard": (HR, "        if default_only && port != default_port {\n            return false;\n        }", "", "test:http::hostrules"),
    # default port only: a plain entry matches any port
    "hostrule_port_plain": (HR, _ALLOWS, _ALLOWS.replace("!default_only || port == default_port", "true"), "test:http::hostrules"),
    # an entry with a port matches any port
    "hostrule_port_entry": (HR, _ALLOWS, _ALLOWS.replace("|p| port == p", "|_| true"), "test:http::hostrules"),
    # a URL's own port is not looked at: the scheme's is
    "hostrule_url_port": (HR, "self.allows(&url.host, url.port, url.default_port())", "self.allows(&url.host, url.default_port(), url.default_port())", "test:http::hostrules"),
    # the default port is https's whatever the scheme
    "hostrule_url_default": (HR, "self.allows(&url.host, url.port, url.default_port())", "self.allows(&url.host, url.port, 443)", "test:http::hostrules"),
    # an alternative is learned whatever the rule says of its host and port
    "hostrule_alt_svc": (H3T, " && host_allowed(a.host.as_deref().unwrap_or(&key.host), a.port)", "", "test:h3_transport"),
    # an alternative with no host is the origin's, and the rule is not asked about its port
    "hostrule_alt_svc_port": (H3T, "host_allowed(a.host.as_deref().unwrap_or(&key.host), a.port)", "host_allowed(a.host.as_deref().unwrap_or(&key.host), key.port)", "test:h3_transport"),
    # a client's rule is not given to Alt-Svc learning
    "hostrule_alt_svc_open": (HTTP, "&|host, port| hosts.map_or(true, |rules| rules.allows(host, port, 443))", "&|_, _| true", "itest:h3_client_interop:alt_svc_makes"),
    # the limits on a URL: a length of exactly the limit is refused
    "urllimit_length_edge": (URLRS, "if text.len() > max {", "if text.len() >= max {", "test:http::url::tests"),
    # a length is of characters, not of bytes
    "urllimit_length_chars": (URLRS, "if text.len() > max {", "if text.chars().count() > max {", "test:http::url::tests"),
    # a length is not looked at
    "urllimit_length_off": (URLRS, "if let Some(max) = self.max_length {", "if let Some(max) = self.max_length.filter(|_| false) {", "test:http::url::tests"),
    # a space is printable
    "urllimit_space": (URLRS, "(0x21..=0x7e).contains(&b)", "(0x20..=0x7e).contains(&b)", "test:http::url::tests"),
    # a DEL is printable
    "urllimit_del": (URLRS, "(0x21..=0x7e).contains(&b)", "(0x21..=0x7f).contains(&b)", "test:http::url::tests"),
    # a byte over 0x7f is printable
    "urllimit_high": (URLRS, "(0x21..=0x7e).contains(&b)", "((0x21..=0x7e).contains(&b) || b >= 0x80)", "test:http::url::tests"),
    # printable ASCII is not looked at
    "urllimit_printable_off": (URLRS, "if self.printable_ascii && !text.bytes()", "if false && !text.bytes()", "test:http::url::tests"),
    # credentials are let through
    "urllimit_credentials": (URLRS, "if self.no_credentials && url.userinfo.is_some() {", "if false && url.userinfo.is_some() {", "test:http::url::tests"),
    # a scheme other than https is let through
    "urllimit_https": (URLRS, "if self.https_only && !url.is_https() {", "if false && !url.is_https() {", "test:http::url::tests"),
    # the strictest set is not all of them (no limit on length)
    "urllimit_strict_length": (URLRS, "UrlLimits { max_length: Some(2048), printable_ascii: true, no_credentials: true, https_only: true }", "UrlLimits { max_length: None, printable_ascii: true, no_credentials: true, https_only: true }", "test:http::url::tests"),
    # the strictest set's length is 2049
    "urllimit_strict_2049": (URLRS, "UrlLimits { max_length: Some(2048), printable_ascii", "UrlLimits { max_length: Some(2049), printable_ascii", "test:http::url::tests"),
})

# The hook that gives each hop its own headers (`Client::hop_headers`): what it gives is a host's credentials, so each way of giving them to the
# wrong hop (or of not checking what is given) is a bug the tests have to find.
_GR = "self.granted_for(&HopInfo { url: &next, method, hop: *hops, from: Some(&hop.url) })?"
MUTANTS.update({
    # the request itself is not given what the hook says
    "hook_start_skipped": (HTTP, "let granted = self.granted_for(&HopInfo { url: &url, method: &method, hop: 0, from: None })?;", "let granted = Vec::new();", "test:http::egress_tests"),
    # a redirect is not given what the hook says
    "hook_follow_skipped": (HTTP, "let granted = " + _GR + ";", "let granted = Vec::new();", "test:http::egress_tests"),
    # the next hop keeps what the hook gave the one before (a token goes to the host a redirect names)
    "hook_stale": (HTTP, "        hop.granted = granted;\n", "        let _ = granted;\n", "test:http::egress_tests"),
    # what the hook gives piles up from hop to hop
    "hook_piles_up": (HTTP, "        hop.granted = granted;\n", "        hop.granted.extend(granted);\n", "test:http::egress_tests"),
    # what the hook gives is carried by the redirect as the caller's headers are
    "hook_carried": (HTTP, "        hop.granted = granted;\n", "        hop.headers.extend(granted.iter().cloned());\n        hop.granted = granted;\n", "test:http::egress_tests"),
    # the hook is told the method the request had, not the one the hop is sent with
    "hook_method": (HTTP, "        let method = if drop_body { \"GET\" } else { hop.method.as_str() };", "        let method = hop.method.as_str();", "test:http::egress_tests"),
    # the hook is told every redirect is the first
    "hook_hop_number": (HTTP, "method, hop: *hops, from: Some(&hop.url) }", "method, hop: 0, from: Some(&hop.url) }", "test:http::egress_tests"),
    # the hook is not told where a redirect came from
    "hook_from": (HTTP, "method, hop: *hops, from: Some(&hop.url) }", "method, hop: *hops, from: None }", "test:http::egress_tests"),
    # a crossing is not one
    "hook_crossing": (HTTP, "from.origin() != self.url.origin()", "from.origin() == self.url.origin()", "test:http::egress_tests"),
    # the hook is asked about a URL before the host rule has judged it
    "hook_before_rule": (HTTP, "        self.check_target(&url, 0)?;\n        let method = method.to_ascii_uppercase();\n        let granted = self.granted_for(&HopInfo { url: &url, method: &method, hop: 0, from: None })?;", "        let method = method.to_ascii_uppercase();\n        let granted = self.granted_for(&HopInfo { url: &url, method: &method, hop: 0, from: None })?;\n        self.check_target(&url, 0)?;", "test:http::egress_tests"),
    # a header of the hook's does not replace the caller's of that name
    "hook_replace": (HTTP, ".filter(|(n, _)| !hop.granted.iter().any(|(g, _)| g.eq_ignore_ascii_case(n)))", ".filter(|_| true)", "test:http::egress_tests"),
    # a header of the hook's is not checked (a line break in a value)
    "hook_unchecked": (HTTP, "if !wire::is_valid_header_name(name) || !wire::is_valid_header_value(value) {", "if false {", "test:http::egress_tests"),
    # a header the client owns can be given by the hook (and is quietly dropped)
    "hook_own_header": (HTTP, "if OWN_HEADERS.iter().any(|own| name.eq_ignore_ascii_case(own)) {", "if false {", "test:http::egress_tests"),
    # the error for a bad header says the value
    "hook_value_in_error": (HTTP, "format!(\"invalid header {name:?} from the hop hook\")", "format!(\"invalid header {name:?}: {value:?} from the hop hook\")", "test:http::egress_tests"),
    # a refusal of the hook is not one
    "hook_refusal": (HTTP, "        let granted = hook(info).map_err(|e| match e {", "        let granted = hook(info).or_else(|_| Ok::<_, Error>(Vec::new())).map_err(|e| match e {", "test:http::egress_tests"),
})

# The error a refusal is: its own kind, with the hop it was and the rule that said it (what a caller reports as "redirect blocked").
ERR = "src/error.rs"
MUTANTS.update({
    # a hook that refuses with an error of its own is an HTTP error, not a refusal
    "refused_hook_kind": (HTTP, "Error::Http(reason) => Error::Refused(Refused { hop: info.hop, by: RefusedBy::Hook, reason }),", "Error::Http(reason) => Error::Http(reason),", "test:http::egress_tests"),
    # a hook that refuses with a refusal keeps a hop number of its own
    "refused_hook_hop": (HTTP, "Error::Refused(r) => Error::Refused(Refused { hop: info.hop, ..r }),", "Error::Refused(r) => Error::Refused(r),", "test:http::egress_tests"),
    # a hook's refusal of any other kind says nothing of who refused
    "refused_hook_by": (HTTP, "Error::Refused(Refused { hop: info.hop, by: RefusedBy::Hook, reason: other.to_string() }),", "Error::Refused(Refused { hop: info.hop, by: RefusedBy::HostRule, reason: other.to_string() }),", "test:http::egress_tests"),
    # a redirect refused by a limit is said to be hop 0 (the request, not the redirect)
    "refused_location_hop": (HTTP, "        self.check_text(&location, *hops)?;\n", "        self.check_text(&location, 0)?;\n", "test:http::egress_tests"),
    # the target of a redirect is judged as hop 0
    "refused_target_hop": (HTTP, "        self.check_target(&next, *hops)?;", "        self.check_target(&next, 0)?;", "test:http::egress_tests"),
    # a redirect to plain http is refused by the wrong rule
    "refused_scheme_by": (HTTP, "Error::Refused(Refused { hop: *hops, by: RefusedBy::Scheme, reason: \"refusing redirect from https to plain http\".into() })", "Error::Refused(Refused { hop: *hops, by: RefusedBy::HostRule, reason: \"refusing redirect from https to plain http\".into() })", "test:http::egress_tests"),
    # plain http after a redirect is said to be refused at hop 0
    "refused_plain_http_hop": (HTTP, "                hop: hop.index,\n                by: RefusedBy::Scheme,", "                hop: 0,\n                by: RefusedBy::Scheme,", "test:http::egress_tests"),
    # a hop does not know which one it is
    "refused_index_kept": (HTTP, "        hop.index = *hops;\n", "", "test:http::egress_tests"),
    # a host that the rule refuses is said to be refused by a limit
    "refused_rule_by": (HTTP, "                by: RefusedBy::HostRule,\n                reason: format!(\"host not allowed", "                by: RefusedBy::UrlLimit,\n                reason: format!(\"host not allowed", "test:http::egress_tests"),
    # the redirect of a refusal is not one
    "refused_is_redirect": (ERR, "        self.hop > 0\n", "        self.hop > 1\n", "test:http::egress_tests"),
    # a request is said to be a redirect
    "refused_display_hop": (ERR, "if self.hop == 0 {\n            write!(f, \"request refused", "if self.hop == 1 {\n            write!(f, \"request refused", "test:http::egress_tests"),
})

# What a client decides about a request and its redirects, found by the fuzz target `egress` alone (the unit tests have these too), and the AEAD
# kernels held to the portable code by `aead`.
_CHA = "src/crypto/chacha20poly1305.rs"
MUTANTS.update({
    # an address that a wildcard ends like is let through
    "egress_wild_number": (HR, "        if ends_in_a_number(host) {\n            return false;\n        }", "        if false {\n            return false;\n        }", "egress", 40),
    # a plain entry matches a host on any port, with the default port only
    "egress_port_wildcard": (HR, "        if default_only && port != default_port {\n            return false;\n        }", "", "egress", 40),
    # what the hook gave for one hop stays for the next
    "egress_stale_grant": (HTTP, "        hop.granted = granted;\n        hop.index = *hops;", "        let _ = granted;\n        hop.index = *hops;", "egress", 40),
    # a redirect from https to plain http is followed
    "egress_downgrade": (HTTP, "        if hop.url.is_https() && !next.is_https() {", "        if false && hop.url.is_https() && !next.is_https() {", "egress", 40),
    # the caller's credentials follow a redirect to another origin
    "egress_credentials_follow": (HTTP, "        if next.origin() != hop.url.origin() {", "        if false && next.origin() != hop.url.origin() {", "egress", 40),
    # the URL a redirect resolves to is not measured
    "egress_resolved_length": (HTTP, "        self.check_text(&next.to_string(), *hops)?;\n", "", "egress", 40),
    # a header of the hook does not replace the caller's of that name
    "egress_hook_replace": (HTTP, ".filter(|(n, _)| !hop.granted.iter().any(|(g, _)| g.eq_ignore_ascii_case(n)))", ".filter(|_| true)", "egress", 40),
    # the vector ChaCha20 kernel's counter goes up by 3 where it handles 4 blocks
    "aead_chacha_counter": (_CHA, "            counter = counter.wrapping_add(4);\n        }\n        rest = chunks.into_remainder();", "            counter = counter.wrapping_add(3);\n        }\n        rest = chunks.into_remainder();", "aead", 40),
})

# (the two that the model server found slowly or not at all have a unit test as well: one byte, and trailers that come before the end of the stream)
for _name in ("h3_conn_ready_trailers", "h3_conn_ready_unread"):
    _file, _old, _new = MUTANTS[_name][:3]
    MUTANTS[_name + "_unit"] = (_file, _old, _new, "test:h3::connection::tests::a_stream_is_ready")

# The client's use of HTTP/3 (`h3_transport.rs` and `h3_step` in `http/mod.rs`): what it does when the network, the origin or the server is
# not what it hoped is checked against aioquic (`tests/h3_client_interop.rs`; needs AIOQUIC_PATH) and by the registry's unit tests.
MUTANTS.update({
    # a dial that failed is not remembered: every request pays for it again
    "h3c_no_backoff": (H3T, "            origin.dialing = false;\n            let failures = origin.backoff.as_ref().map_or(0, |b| b.failures).saturating_add(1);\n            origin.backoff = Some(Backoff { until: Instant::now() + backoff_for(failures), failures });", "            origin.dialing = false;", "itest:h3_client_interop:a_network_that_drops_udp"),
    # what the origin says in Alt-Svc is not noted
    "h3c_no_learn": (HTTP, "        h3.registry.learn(&key, resp.headers_named(\"alt-svc\"), &|host, port| hosts.map_or(true, |rules| rules.allows(host, port, 443)));", "        let _ = (&h3, &key, resp, hosts);", "itest:h3_client_interop:alt_svc_makes"),
    # `clear` does not close what was made
    "h3c_clear_keeps_connection": (H3T, "                for c in &origin.conns {\n                    c.drain();\n                }\n", "", "itest:h3_client_interop:alt_svc_clear"),
    # a client that assumes QUIC does not try it
    "h3c_eager_skips": (H3T, "                (None, true) => (host.to_string(), port),", "                (None, true) => return Acquired::Skip,", "itest:h3_client_interop:a_request_over_http3"),
    # an alternative that cannot be reached fails the request instead of going the TCP way
    "h3c_dial_failure_fails": (HTTP, "                    Err(_) => {\n                        ticket.failed();\n                        return Ok(H3Step::Skip);\n                    }", "                    Err(e) => {\n                        ticket.failed();\n                        return Err(e);\n                    }", "itest:h3_client_interop:an_alternative_nobody"),
    # a request without keep-alive goes over QUIC (which is reuse)
    "h3c_keep_alive": (HTTP, "let h3_on = self.h3.is_some() && url.is_https() && proxy.is_none() && self.policy.parks();", "let h3_on = self.h3.is_some() && url.is_https() && proxy.is_none();", "itest:h3_client_interop:http3_is_not_used_without"),
    # a request through a proxy goes over QUIC, around the proxy
    "h3c_proxy": (HTTP, "let h3_on = self.h3.is_some() && url.is_https() && proxy.is_none() && self.policy.parks();", "let h3_on = self.h3.is_some() && url.is_https() && self.policy.parks();", "itest:h3_client_interop:http3_is_not_used_through"),
    # the size limit is not enforced on a body whose length is not declared
    "h3c_collect_limit": (H3T, "                    if body.len() as u64 > limit {", "                    if false && body.len() as u64 > limit {", "itest:h3_client_interop:a_body_over_the_limit"),
    # a streamed body is not counted
    "h3c_stream_limit": (HTTP.replace("mod.rs", "stream.rs"), "                if self.seen > self.max {\n                    self.failed = true;", "                if false && self.seen > self.max {\n                    self.failed = true;", "itest:h3_client_interop:a_body_over_the_limit"),
    # a connection that was new and did not carry an answer leaves nothing behind
    "h3c_broken_forgotten": (HTTP, "            support.registry.broken(key);\n", "", "itest:h3_client_interop:a_new_connection_that_dies"),
    # a client that is dropped closes its connections at once, with the responses that are being read
    "h3c_retire_closes": (H3T, "    pub(super) fn retire(&self) {\n        self.drain();\n    }", "    pub(super) fn retire(&self) {\n        let mut g = self.lock();\n        self.close_locked(&mut g);\n    }", "itest:h3_client_interop:a_response_that_is_being_read"),
    # a request that may not be repeated is sent again when its connection dies
    "h3c_post_repeated": (HTTP, "        if failure.peer_closed && tries.repeat_allowed {\n            tries.repeat_allowed = false;\n            if reused {", "        if failure.peer_closed {\n            tries.repeat_allowed = false;\n            if reused {", "itest:h3_client_interop:a_request_that_may_not"),
    # the origin's own `clear` is not heeded by a client that assumes QUIC
    "h3c_clear_no_backoff": (H3T, "                if origin.backoff.is_none() {\n                    origin.backoff = Some(Backoff { until: Instant::now() + BACKOFF_BASE, failures: 0 });\n                }\n", "", "test:h3_transport"),
    # a new advertisement does not end the time that the origin's own `clear` set
    "h3c_advert_keeps_clear": (H3T, "                if origin.backoff.as_ref().is_some_and(|b| b.failures == 0) {\n                    origin.backoff = None;\n                }\n", "", "test:h3_transport"),
})

# --- HTTP/2: the body straight into the buffer of the caller who reads (B-87) ------------------------------------------------
H2C = "src/http/h2/connection.rs"
H2T = "src/http/h2_transport.rs"
MUTANTS.update({
    # bytes go to the reader past bytes the stream holds unread (out of order)
    "b87_past_unread": (H2C, "if !s.collecting && s.head.is_none() && s.unread() == 0 {", "if !s.collecting && s.head.is_none() {", "h2_client"),
    # bytes go to the reader before the head was taken
    "b87_before_head": (H2C, "if !s.collecting && s.head.is_none() && s.unread() == 0 {", "if !s.collecting && s.unread() == 0 {", "test:h2::connection::tests::nothing_goes_straight"),
    # a stream that collects has its body written to a reader's buffer
    "b87_collecting": (H2C, "if !s.collecting && s.head.is_none() && s.unread() == 0 {", "if s.head.is_none() && s.unread() == 0 {", "h2_client"),
    # the body of any stream goes to the reader's buffer
    "b87_any_stream": (H2C, "if let Some(d) = direct.filter(|d| d.stream == id) {", "if let Some(d) = direct {", "h2_client"),
    # what is written to the reader gets no credit
    "b87_no_credit": (H2C, "                    if read > 0 {\n                        self.announce_stream(id);\n                        self.credit_connection(read as u32);\n                    }", "", "h2_client"),
    # what does not fit is lost
    "b87_spill_lost": (H2C, "                        s.body.extend_from_slice(&bytes[read..]);", "", "h2_client"),
    # what does not fit is not news
    "b87_spill_not_news": (H2C, "                    if read < n {\n                        self.news.touch(id);", "                    if false {\n                        self.news.touch(id);", "test:h2::connection::tests::bytes_read_straight_are_not_news"),
    # a full buffer does not stop the decryption: the rest goes through the stream's buffer
    "b87_no_stop": (H2T, "            if direct.as_ref().is_some_and(|d| d.full()) {", "            if false && direct.as_ref().is_some_and(|d| d.full()) {", "test:what_a_full_buffer"),
    # what a full buffer left is not said to be left: it waits for the socket to bring something
    "b87_left_unsaid": (H2T, "                side.undigested = true;\n                break;", "                break;", "test:h2_client_tests"),
    # what was left is not taken in before the socket is read
    "b87_left_after_socket": (H2T, "        if side.undigested {", "        if false && side.undigested {", "test:h2_client_tests"),
})

# --- HTTP/2: threads on one connection read and send for each other (B-89) -----------------------------------------------------
MUTANTS.update({
    # a caller that lets go of the right to read gives it to nobody else
    "b89_no_handoff": (H2T, "        if !self.closing {\n            let next = self.slots.iter()", "        if false {\n            let next = self.slots.iter()", "test:h2_transport::tests"),
    # ... and gives it to a caller who waits to send a body (and cannot read)
    "b89_handoff_to_sender": (H2T, "id != stream && slot.waiting.load(Ordering::Relaxed) && slot.can_lead.load(Ordering::Relaxed)", "id != stream && slot.waiting.load(Ordering::Relaxed)", "test:h2_transport::tests"),
    # the writer thread is never told
    "b89_writer_never_told": (H2T, "        if self.writer_asleep.load(Ordering::SeqCst) {", "        if false && self.writer_asleep.load(Ordering::SeqCst) {", "test:h2_client_tests"),
    # the writer thread does not say that it sleeps
    "b89_writer_asleep_unsaid": (H2T, "                    self.writer_asleep.store(true, Ordering::SeqCst);\n", "", "test:h2_client_tests"),
    # a caller that finds the outbox taken does not say so
    "b89_wanted_unsaid": (H2T, "        self.write_wanted.store(true, Ordering::SeqCst);\n        std::sync::atomic::fence(Ordering::SeqCst);\n", "", "test:h2_client_tests"),
    # whoever has the outbox does not look whether somebody wanted it
    "b89_wanted_unheeded": (H2T, "            if !self.write_wanted.load(Ordering::SeqCst) {\n                return;\n            }", "            return;", "test:h2_client_tests"),
    # what a caller's read leaves HTTP/2 to say is not said
    "b89_send_after_dropped": (H2T, "        if send {\n            // what the read left", "        if false && send {\n            // what the read left", "test:h2_client_tests"),
    # what giving a stream up queues is not sent
    "b89_drop_unsent": (H2T, "        } else if queued {\n            shared.send_now();", "        } else if false && queued {\n            shared.send_now();", "test:h2_client_tests"),
})

# --- HTTP/1.1: fewer system calls for a request on a connection used again (B-90) ----------------------------------------------
NET = "src/asyncio/net.rs"
MUTANTS.update({
    # a timeout is never set again once one was
    "b90_timeouts_never_set": (NET, "        if slot.load(Ordering::Relaxed) == v {", "        if slot.load(Ordering::Relaxed) != 0 || true {", "test:asyncio::net"),
    # a peer that sent something or hung up looks quiet
    "b90_peek_says_quiet": (NET, "                // a byte (something is waiting) or end of file (the peer hung up)\n                return Some(false);", "                return Some(true);", "test:asyncio::net"),
    # a quiet peer does not look quiet (no connection is used again)
    "b90_peek_never_quiet": (NET, "                std::io::ErrorKind::WouldBlock => return Some(true),", "                std::io::ErrorKind::WouldBlock => return Some(false),", "test:pool_tests"),
    # the read buffer of a finished response is not kept
    "b90_scratch_dropped": (HTTP.replace("mod.rs", "stream.rs"), "            SPARE_SCRATCH.with(|s| s.set(Some(spare)));", "            drop(spare);", "test:pool_tests::the_read_buffer"),
})

# --- QUIC: key updates the client starts, keep-alive (B-91) ---------------------------------------------------------------------
MUTANTS.update({
    # a key update does not wait for an acknowledgment of a packet sent with the keys in use
    "b91_update_unacked": (Q + "connection.rs", "        if !p.tx_acked || p.rx_phase != p.tx_phase {\n            return false;", "        if p.rx_phase != p.tx_phase {\n            return false;", "test:quic::connection"),
    # the keys are never updated by themselves
    "b91_never_updated": (Q + "connection.rs", "        if self.phases.is_none() {\n            return;\n        }\n        let (sealed, limit)", "        if true {\n            return;\n        }\n        let (sealed, limit)", "test:quic::connection"),
    # an acknowledgment of a packet from before the update counts for the keys now
    "b91_any_ack": (Q + "connection.rs", "            if let Some(p) = self.phases.as_mut().filter(|p| a.largest >= p.tx_first_pn) {", "            if let Some(p) = self.phases.as_mut() {", "test:quic::connection"),
    # keep-alive sends nothing
    "b91_no_keep_alive": (Q + "connection.rs", "        if self.keep_alive_at().is_some_and(|t| now >= t) {\n            self.ping_pending = true;", "        if self.keep_alive_at().is_some_and(|t| now >= t) {\n            self.ping_pending = false;", "test:quic::connection"),
    # keep-alive PINGs keep a connection to a peer that never answers alive
    "b91_keep_alive_restarts_idle": (Q + "connection.rs", "            self.last_keep_alive = Some(now);\n", "            self.last_keep_alive = Some(now);\n            self.last_activity = now;\n", "test:quic::connection"),
})

EQUIVALENT = {
    "connection_stream_acked_twice": "acknowledging a chunk twice is the same as once (acknowledgments are idempotent by design)",
    "connection_crypto_acked_never": "the buffers of the handshake's crypto data are dropped with the keys of their space, and the client sends none later",
}
