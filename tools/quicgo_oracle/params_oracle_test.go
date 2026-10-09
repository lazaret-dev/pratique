package wire

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// spans gives where each parameter of a well-formed list begins and ends.
func spans(b []byte) [][2]int {
	var out [][2]int
	for at := 0; at < len(b); {
		_, l1, err := quicvarint.Parse(b[at:])
		if err != nil {
			break
		}
		n, l2, err := quicvarint.Parse(b[at+l1:])
		if err != nil {
			break
		}
		end := at + l1 + l2 + int(n)
		out = append(out, [2]int{at, end})
		at = end
	}
	return out
}

// describeParams gives the same line for a set of transport parameters that the Rust test gives. quic-go keeps some of them
// in other forms (a duration, a pointer, a default that is not the RFC's), which the Rust test undoes where it compares.
func describeParams(p *TransportParameters) string {
	cid := func(c protocol.ConnectionID) string { return hex.EncodeToString(c.Bytes()) }
	rscid := "none"
	if p.RetrySourceConnectionID != nil {
		rscid = cid(*p.RetrySourceConnectionID)
	}
	srt := "none"
	if p.StatelessResetToken != nil {
		srt = hex.EncodeToString(p.StatelessResetToken[:])
	}
	dgram := "none"
	if p.MaxDatagramFrameSize != protocol.InvalidByteCount {
		dgram = fmt.Sprint(p.MaxDatagramFrameSize)
	}
	pa := "none"
	if p.PreferredAddress != nil {
		addr := func(a netip.AddrPort) string {
			if !a.IsValid() {
				return "-"
			}
			return a.String()
		}
		pa = fmt.Sprintf("%s,%s,%s,%x", addr(p.PreferredAddress.IPv4), addr(p.PreferredAddress.IPv6), cid(p.PreferredAddress.ConnectionID), p.PreferredAddress.StatelessResetToken[:])
	}
	return fmt.Sprintf("odcid=%s iscid=%s rscid=%s idle=%d udp=%d data=%d bl=%d br=%d u=%d sb=%d su=%d ade=%d mad=%d dam=%t pa=%s ctl=%d srt=%s dgram=%s",
		cid(p.OriginalDestinationConnectionID), cid(p.InitialSourceConnectionID), rscid, p.MaxIdleTimeout.Milliseconds(), p.MaxUDPPayloadSize,
		p.InitialMaxData, p.InitialMaxStreamDataBidiLocal, p.InitialMaxStreamDataBidiRemote, p.InitialMaxStreamDataUni,
		p.MaxBidiStreamNum, p.MaxUniStreamNum, p.AckDelayExponent, p.MaxAckDelay.Milliseconds(), p.DisableActiveMigration, pa,
		p.ActiveConnectionIDLimit, srt, dgram)
}

func readParams(b []byte, sentBy protocol.Perspective) string {
	var p TransportParameters
	if err := p.Unmarshal(b, sentBy); err != nil {
		return "ERR"
	}
	// parameters that quic-go knows from drafts and the Rust side does not: left out of the comparison
	if p.EnableResetStreamAt || p.MinAckDelay != nil {
		return "SKIP"
	}
	return "OK " + describeParams(&p)
}

func randCID(r *rand.Rand, min int) protocol.ConnectionID {
	return protocol.ParseConnectionID(rbytes(r, min+r.Intn(21-min)))
}

func genParams(r *rand.Rand) (*TransportParameters, protocol.Perspective) {
	pers := protocol.PerspectiveClient
	if r.Intn(2) == 0 {
		pers = protocol.PerspectiveServer
	}
	p := &TransportParameters{
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(r.Int63n(1 << 40)),
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(r.Int63n(1 << 30)),
		InitialMaxStreamDataUni:        protocol.ByteCount(r.Int63n(1 << 20)),
		InitialMaxData:                 protocol.ByteCount(r.Int63n(1 << 50)),
		MaxAckDelay:                    time.Duration(r.Intn(1<<14)) * time.Millisecond,
		AckDelayExponent:               uint8(r.Intn(21)),
		DisableActiveMigration:         r.Intn(2) == 0,
		MaxUDPPayloadSize:              protocol.ByteCount(1200 + r.Intn(1<<20)),
		MaxUniStreamNum:                protocol.StreamNum(r.Int63n(1<<60 + 1)),
		MaxBidiStreamNum:               protocol.StreamNum(r.Int63n(1<<60 + 1)),
		MaxIdleTimeout:                 time.Duration(5000+r.Intn(1<<30)) * time.Millisecond,
		InitialSourceConnectionID:      randCID(r, 0),
		ActiveConnectionIDLimit:        uint64(2 + r.Intn(1<<20)),
		MaxDatagramFrameSize:           protocol.InvalidByteCount,
	}
	if r.Intn(3) == 0 {
		p.MaxDatagramFrameSize = protocol.ByteCount(r.Intn(1 << 16))
	}
	if r.Intn(4) == 0 {
		p.MaxAckDelay = 25 * time.Millisecond
	}
	if r.Intn(4) == 0 {
		p.AckDelayExponent = 3
	}
	if r.Intn(4) == 0 {
		p.ActiveConnectionIDLimit = 2
	}
	if pers == protocol.PerspectiveServer {
		p.OriginalDestinationConnectionID = randCID(r, 0)
		if r.Intn(2) == 0 {
			t := protocol.StatelessResetToken{}
			copy(t[:], rbytes(r, 16))
			p.StatelessResetToken = &t
		}
		if r.Intn(2) == 0 {
			c := randCID(r, 0)
			p.RetrySourceConnectionID = &c
		}
		if r.Intn(2) == 0 {
			pa := &PreferredAddress{ConnectionID: randCID(r, 1)}
			copy(pa.StatelessResetToken[:], rbytes(r, 16))
			if r.Intn(3) != 0 {
				pa.IPv4 = netip.AddrPortFrom(netip.AddrFrom4([4]byte{byte(1 + r.Intn(254)), 2, 3, 4}), uint16(1+r.Intn(65535)))
			}
			if r.Intn(3) != 0 {
				var a [16]byte
				copy(a[:], rbytes(r, 16))
				a[0] |= 1
				pa.IPv6 = netip.AddrPortFrom(netip.AddrFrom16(a), uint16(1+r.Intn(65535)))
			}
			p.PreferredAddress = pa
		}
	}
	return p, pers
}

func TestZZParamsOracle(t *testing.T) {
	r := rand.New(rand.NewSource(20261007))
	out, err := os.Create(os.Getenv("ORACLE_PARAMS_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()
	emit := func(b []byte, flag byte) {
		for _, s := range []struct {
			c byte
			p protocol.Perspective
		}{{'C', protocol.PerspectiveClient}, {'S', protocol.PerspectiveServer}} {
			res := readParams(b, s.p)
			if res == "SKIP" {
				continue
			}
			fmt.Fprintf(w, "%c%c %s %s\n", s.c, flag, hex.EncodeToString(b), res)
		}
	}
	for i := 0; i < 400; i++ {
		p, pers := genParams(r)
		b := p.Marshal(pers)
		emit(b, 'V')
		for k := 0; k < 2; k++ {
			m := append([]byte(nil), b...)
			switch r.Intn(10) {
			case 0:
				m[r.Intn(len(m))] = byte(r.Intn(256))
			case 1:
				m = m[:r.Intn(len(m))]
			case 2:
				m = append(m, byte(r.Intn(256)))
			case 3:
				j := r.Intn(len(m))
				m = append(m[:j], append([]byte{byte(r.Intn(256))}, m[j:]...)...)
			case 4:
				// one more parameter: a known id with a random value, or an unknown one
				id := byte(r.Intn(0x22))
				m = append(m, id, byte(r.Intn(6)))
				m = append(m, rbytes(r, int(m[len(m)-1]))...)
			case 5:
				// a parameter of the list sent twice
				sp := spans(m)
				one := sp[r.Intn(len(sp))]
				m = append(m, m[one[0]:one[1]]...)
			case 6:
				// the value of one parameter replaced by random bytes of the same length
				sp := spans(m)
				one := sp[r.Intn(len(sp))]
				if one[1] > one[0] {
					for at := one[1] - 1; at >= one[0]+2 && r.Intn(3) != 0; at-- {
						m[at] = byte(r.Intn(256))
					}
				}
			case 7:
				// a parameter that nobody knows
				m = quicvarint.Append(m, 0x30+uint64(r.Intn(1<<20)))
				v := rbytes(r, r.Intn(30))
				m = quicvarint.Append(m, uint64(len(v)))
				m = append(m, v...)
			case 8:
				// the parameters in another order
				sp := spans(m)
				r.Shuffle(len(sp), func(i, j int) { sp[i], sp[j] = sp[j], sp[i] })
				m = m[:0:0]
				for _, one := range sp {
					m = append(m, b[one[0]:one[1]]...)
				}
			case 9:
				// one parameter left out
				sp := spans(m)
				one := sp[r.Intn(len(sp))]
				m = append(append([]byte(nil), b[:one[0]]...), b[one[1]:]...)
			}
			emit(m, 'M')
		}
	}
	for i := 0; i < 200; i++ {
		emit(rbytes(r, r.Intn(40)), 'M')
	}
}
