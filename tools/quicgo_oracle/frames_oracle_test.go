package wire

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// describe gives the same line for a frame that the Rust test gives.
func describe(f Frame) string {
	switch f := f.(type) {
	case *PingFrame:
		return "PING"
	case *ResetStreamFrame:
		return fmt.Sprintf("RESET_STREAM id=%d err=%d final=%d", f.StreamID, f.ErrorCode, f.FinalSize)
	case *StopSendingFrame:
		return fmt.Sprintf("STOP_SENDING id=%d err=%d", f.StreamID, f.ErrorCode)
	case *CryptoFrame:
		return fmt.Sprintf("CRYPTO off=%d data=%x", f.Offset, f.Data)
	case *NewTokenFrame:
		return fmt.Sprintf("NEW_TOKEN token=%x", f.Token)
	case *StreamFrame:
		return fmt.Sprintf("STREAM id=%d off=%d fin=%t data=%x", f.StreamID, f.Offset, f.Fin, f.Data)
	case *MaxDataFrame:
		return fmt.Sprintf("MAX_DATA %d", f.MaximumData)
	case *MaxStreamDataFrame:
		return fmt.Sprintf("MAX_STREAM_DATA id=%d max=%d", f.StreamID, f.MaximumStreamData)
	case *MaxStreamsFrame:
		return fmt.Sprintf("MAX_STREAMS bidi=%t max=%d", f.Type == protocol.StreamTypeBidi, f.MaxStreamNum)
	case *DataBlockedFrame:
		return fmt.Sprintf("DATA_BLOCKED %d", f.MaximumData)
	case *StreamDataBlockedFrame:
		return fmt.Sprintf("STREAM_DATA_BLOCKED id=%d limit=%d", f.StreamID, f.MaximumStreamData)
	case *StreamsBlockedFrame:
		return fmt.Sprintf("STREAMS_BLOCKED bidi=%t limit=%d", f.Type == protocol.StreamTypeBidi, f.StreamLimit)
	case *NewConnectionIDFrame:
		return fmt.Sprintf("NEW_CONNECTION_ID seq=%d retire=%d cid=%x token=%x", f.SequenceNumber, f.RetirePriorTo, f.ConnectionID.Bytes(), f.StatelessResetToken[:])
	case *RetireConnectionIDFrame:
		return fmt.Sprintf("RETIRE_CONNECTION_ID %d", f.SequenceNumber)
	case *PathChallengeFrame:
		return fmt.Sprintf("PATH_CHALLENGE %x", f.Data[:])
	case *PathResponseFrame:
		return fmt.Sprintf("PATH_RESPONSE %x", f.Data[:])
	case *ConnectionCloseFrame:
		if f.IsApplicationError {
			return fmt.Sprintf("CONNECTION_CLOSE app code=%d reason=%x", f.ErrorCode, f.ReasonPhrase)
		}
		return fmt.Sprintf("CONNECTION_CLOSE transport code=%d type=%d reason=%x", f.ErrorCode, f.FrameType, f.ReasonPhrase)
	case *HandshakeDoneFrame:
		return "HANDSHAKE_DONE"
	}
	panic(fmt.Sprintf("no description for %T", f))
}

func describeAck(f *AckFrame, raw uint64) string {
	var rs []string
	for _, r := range f.AckRanges {
		rs = append(rs, fmt.Sprintf("%d-%d", r.Largest, r.Smallest))
	}
	ecn := "-"
	return fmt.Sprintf("ACK largest=%d delay=%d ranges=%s ecn=%s", f.AckRanges[0].Largest, raw, strings.Join(rs, ","), ecn)
}

// parsePayload reads a payload the way a QUIC endpoint of quic-go does, with the one rule of the RFC that its parser leaves out
// (a frame type in the fewest bytes), and gives the frames one after another, ending in ERR if there was an error.
func parsePayload(b []byte, lvl protocol.EncryptionLevel) string {
	p := NewFrameParser(false, false, false)
	var out []string
	for len(b) > 0 {
		typ, l, err := quicvarint.Parse(b)
		if err != nil || l != quicvarint.Len(typ) {
			out = append(out, "ERR")
			break
		}
		if typ == 0 {
			b = b[l:]
			continue
		}
		ft, n, err := p.ParseType(b, lvl)
		if err != nil {
			out = append(out, "ERR")
			break
		}
		b = b[n:]
		var consumed int
		switch {
		case ft.IsStreamFrameType():
			f, c, err := p.ParseStreamFrame(ft, b, protocol.Version1)
			if err != nil {
				out = append(out, "ERR")
				return strings.Join(out, ";")
			}
			consumed = c
			out = append(out, describe(f))
		case ft.IsAckFrameType():
			// the delay as it was sent: the second number of the frame
			_, l1, _ := quicvarint.Parse(b)
			raw, _, _ := quicvarint.Parse(b[l1:])
			f, c, err := p.ParseAckFrame(ft, b, lvl, protocol.Version1)
			if err != nil {
				out = append(out, "ERR")
				return strings.Join(out, ";")
			}
			consumed = c
			d := describeAck(f, raw)
			if ft == FrameTypeAckECN {
				d = strings.TrimSuffix(d, "ecn=-") + fmt.Sprintf("ecn=%d,%d,%d", f.ECT0, f.ECT1, f.ECNCE)
			}
			out = append(out, d)
		default:
			f, c, err := p.ParseLessCommonFrame(ft, b, protocol.Version1)
			if err != nil {
				out = append(out, "ERR")
				return strings.Join(out, ";")
			}
			consumed = c
			out = append(out, describe(f))
		}
		b = b[consumed:]
	}
	return strings.Join(out, ";")
}

func rv(r *rand.Rand) uint64 {
	switch r.Intn(6) {
	case 0:
		return []uint64{0, 1, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1}[r.Intn(9)]
	default:
		bits := uint(r.Intn(63))
		if bits == 0 {
			return 0
		}
		return r.Uint64() >> (64 - bits)
	}
}

func rbytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	r.Read(b)
	return b
}

func genFrame(r *rand.Rand, last bool) []byte {
	v := protocol.Version1
	var f Frame
	switch r.Intn(21) {
	case 0:
		f = &PingFrame{}
	case 1:
		f = &ResetStreamFrame{StreamID: protocol.StreamID(rv(r)), ErrorCode: 0, FinalSize: protocol.ByteCount(rv(r))}
		f.(*ResetStreamFrame).ErrorCode = 0
	case 2:
		f = &StopSendingFrame{StreamID: protocol.StreamID(rv(r)), ErrorCode: 0}
	case 3:
		d := rbytes(r, r.Intn(40))
		off := protocol.ByteCount(rv(r) >> uint(r.Intn(40)))
		f = &CryptoFrame{Offset: off, Data: d}
	case 4:
		f = &NewTokenFrame{Token: rbytes(r, 1+r.Intn(30))}
	case 5, 6:
		d := rbytes(r, r.Intn(50))
		off := protocol.ByteCount(0)
		if r.Intn(2) == 0 {
			off = protocol.ByteCount(rv(r) >> uint(r.Intn(40)))
		}
		fin := r.Intn(2) == 0 || len(d) == 0
		f = &StreamFrame{StreamID: protocol.StreamID(rv(r)), Offset: off, Data: d, Fin: fin, DataLenPresent: !last || r.Intn(2) == 0}
	case 7:
		f = &MaxDataFrame{MaximumData: protocol.ByteCount(rv(r))}
	case 8:
		f = &MaxStreamDataFrame{StreamID: protocol.StreamID(rv(r)), MaximumStreamData: protocol.ByteCount(rv(r))}
	case 9:
		f = &MaxStreamsFrame{Type: protocol.StreamType(r.Intn(2)), MaxStreamNum: protocol.StreamNum(rv(r) >> 2)}
	case 10:
		f = &DataBlockedFrame{MaximumData: protocol.ByteCount(rv(r))}
	case 11:
		f = &StreamDataBlockedFrame{StreamID: protocol.StreamID(rv(r)), MaximumStreamData: protocol.ByteCount(rv(r))}
	case 12:
		f = &StreamsBlockedFrame{Type: protocol.StreamType(r.Intn(2)), StreamLimit: protocol.StreamNum(rv(r) >> 2)}
	case 13:
		seq := rv(r)
		ret := seq
		if seq > 0 && r.Intn(2) == 0 {
			ret = r.Uint64() % (seq + 1)
		}
		nf := &NewConnectionIDFrame{SequenceNumber: seq, RetirePriorTo: ret, ConnectionID: protocol.ParseConnectionID(rbytes(r, 1+r.Intn(20)))}
		copy(nf.StatelessResetToken[:], rbytes(r, 16))
		f = nf
	case 14:
		f = &RetireConnectionIDFrame{SequenceNumber: rv(r)}
	case 15:
		pc := &PathChallengeFrame{}
		copy(pc.Data[:], rbytes(r, 8))
		f = pc
	case 16:
		pr := &PathResponseFrame{}
		copy(pr.Data[:], rbytes(r, 8))
		f = pr
	case 17:
		f = &ConnectionCloseFrame{IsApplicationError: false, ErrorCode: rv(r), FrameType: rv(r), ReasonPhrase: string(rbytes(r, r.Intn(30)))}
	case 18:
		f = &ConnectionCloseFrame{IsApplicationError: true, ErrorCode: rv(r), ReasonPhrase: string(rbytes(r, r.Intn(30)))}
	case 19:
		f = &HandshakeDoneFrame{}
	default:
		// an ACK
		af := &AckFrame{DelayTime: time.Duration(rv(r)>>uint(20+r.Intn(30))) * 8 * time.Microsecond}
		largest := protocol.PacketNumber(rv(r))
		for k := 0; k < 1+r.Intn(5); k++ {
			ln := protocol.PacketNumber(rv(r) >> uint(r.Intn(60)))
			if ln > largest {
				ln = largest
			}
			af.AckRanges = append(af.AckRanges, AckRange{Smallest: largest - ln, Largest: largest})
			gap := protocol.PacketNumber(rv(r) >> uint(r.Intn(60)))
			if largest-ln < gap+2+0 {
				break
			}
			largest = largest - ln - gap - 2
		}
		if r.Intn(3) == 0 {
			af.ECT0, af.ECT1, af.ECNCE = uint64(1+r.Intn(5)), rv(r)>>10, uint64(r.Intn(3))
		}
		f = af
	}
	b, err := f.Append(nil, v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestZZOracle(t *testing.T) {
	r := rand.New(rand.NewSource(20261006))
	out, err := os.Create(os.Getenv("ORACLE_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()
	levels := []struct {
		c byte
		l protocol.EncryptionLevel
	}{{'I', protocol.EncryptionInitial}, {'H', protocol.EncryptionHandshake}, {'1', protocol.Encryption1RTT}}
	emit := func(b []byte, all bool, flag byte) {
		for i, lv := range levels {
			if !all && i < 2 && r.Intn(5) != 0 {
				continue
			}
			fmt.Fprintf(w, "%c%c %s %s\n", lv.c, flag, hex.EncodeToString(b), parsePayload(b, lv.l))
		}
	}
	for i := 0; i < 350; i++ {
		// a valid payload
		var b []byte
		n := 1 + r.Intn(3)
		for k := 0; k < n; k++ {
			if r.Intn(8) == 0 {
				b = append(b, make([]byte, 1+r.Intn(4))...)
			}
			b = append(b, genFrame(r, k == n-1)...)
		}
		emit(b, true, 'V')
		// and changed
		m := append([]byte(nil), b...)
		switch r.Intn(4) {
		case 0:
			m[r.Intn(len(m))] = byte(r.Intn(256))
		case 1:
			m = m[:1+r.Intn(len(m))]
		case 2:
			m = append(m, byte(r.Intn(256)))
		case 3:
			j := r.Intn(len(m))
			m = append(m[:j], append([]byte{byte(r.Intn(256))}, m[j:]...)...)
		}
		emit(m, false, 'M')
	}
	// and nonsense with a frame type at the front
	for i := 0; i < 150; i++ {
		b := rbytes(r, 1+r.Intn(30))
		b[0] = byte(r.Intn(0x22))
		emit(b, false, 'M')
	}
}
