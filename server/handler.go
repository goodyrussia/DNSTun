package main

import (
	"encoding/binary"
	"log"
	"strconv"
	"strings"
	"time"
)

const (
	zoneTTL = 3600 // NS/SOA: cached so resolvers stop probing the zone
	negTTL  = 60   // NODATA on foreign names: brief negative cache
	probeSID = "probe"
)

type Handler struct {
	cfg *Config
	mgr *Manager
	tun *Tun
}

func NewHandler(cfg *Config, mgr *Manager, tun *Tun) *Handler {
	return &Handler{cfg: cfg, mgr: mgr, tun: tun}
}

func (h *Handler) debugf(format string, args ...any) {
	if h.cfg.Debug {
		log.Printf(format, args...)
	}
}

// Handle processes one DNS message and returns the response (nil = drop).
func (h *Handler) Handle(msg []byte, tr transportKind) []byte {
	q, err := parseDNSQuery(msg)
	if err != nil {
		return nil
	}
	labels, _ := splitQueryName(q.Q.Name)
	if len(labels) == 0 || labels[0] == "" {
		return nil
	}
	rest, ok := stripDomain(labels, h.cfg.Domain)
	if !ok {
		// foreign name: answer NODATA so resolvers stop retrying
		return h.nodata(q)
	}
	if len(rest) == 0 {
		// zone apex: NS/SOA keep the delegation healthy
		return h.handleApex(q)
	}
	// response-size probe used by the client to auto-tune its reply budget:
	//   <bytes>.probe.<zone>
	if rest[len(rest)-1] == probeSID {
		if n, err := strconv.Atoi(rest[0]); err == nil {
			return h.sizeProbe(q, n, tr)
		}
		return h.nodata(q)
	}
	if len(rest) < 2 {
		return h.nodata(q)
	}
	sid := rest[len(rest)-1]
	dataLabels := rest[:len(rest)-1]
	s := h.mgr.Get(sid)
	if s == nil {
		h.debugf("unknown sid %q", sid)
		return buildDNSResponse(q, nil, 0) // empty NOERROR, nothing cacheable
	}
	return h.handleData(q, s, dataLabels, tr)
}

// ---------------------------------------------------------------------------
// zone apex: NS / SOA (resolvers need these to treat the zone as valid)
// ---------------------------------------------------------------------------

func (h *Handler) handleApex(q *dnsQuery) []byte {
	switch q.Q.QType {
	case 2: // NS
		return buildDNSResponse(q, []dnsAnswer{{Type: 2, Data: encodeName(h.cfg.NSName), TTL: zoneTTL}}, 0)
	case 6: // SOA
		return buildDNSResponse(q, []dnsAnswer{{Name: q.Q.Name, Type: 6, Data: h.soaRDATA(), TTL: zoneTTL}}, 0)
	default:
		return h.nodata(q)
	}
}

func (h *Handler) soaRDATA() []byte {
	out := encodeName(h.cfg.NSName)
	out = append(out, encodeName("hostmaster."+h.cfg.Domain)...)
	var nums [20]byte
	binary.BigEndian.PutUint32(nums[0:], uint32(time.Now().Unix()/3600))
	binary.BigEndian.PutUint32(nums[4:], 3600)    // refresh
	binary.BigEndian.PutUint32(nums[8:], 600)     // retry
	binary.BigEndian.PutUint32(nums[12:], 86400)  // expire
	binary.BigEndian.PutUint32(nums[16:], negTTL) // SOA minimum
	return append(out, nums[:]...)
}

func (h *Handler) nodata(q *dnsQuery) []byte {
	return buildDNSResponseAuth(q, nil, []dnsAnswer{{Name: h.cfg.Domain, Type: 6, Data: h.soaRDATA(), TTL: negTTL}}, 0)
}

// ---------------------------------------------------------------------------
// tunnel data
// ---------------------------------------------------------------------------

func (h *Handler) handleData(q *dnsQuery, s *Session, dataLabels []string, tr transportKind) []byte {
	s.touch()
	s.Queries.Add(1)

	// ---- speed-test endpoint: a label "s<N>" queues N bytes of test payload ----
	for _, lab := range dataLabels {
		if len(lab) > 1 && lab[0] == 's' {
			if n, err := strconv.Atoi(lab[1:]); err == nil && n > 0 {
				if n > 16<<20 {
					n = 16 << 20
				}
				s.enqueueTestData(n)
			}
		}
	}

	// ---- upstream: decode the base32 blob, reassemble, feed the TUN ----
	if blob, err := b32Decode(strings.Join(dataLabels, "")); err == nil && len(blob) >= 4 {
		if hdr, data, err := decodeUpHdr(blob); err == nil {
			s.UpBytes.Add(uint64(len(data)))
			if len(data) > 0 {
				h.debugf("up: frag id=%d idx=%d more=%d len=%d", hdr.FragID, hdr.FragIdx, hdr.Flags, len(data))
				if pkt := s.addFragment(hdr, data); pkt != nil {
					h.debugf("up: reassembled %dB -> tun", len(pkt))
					if len(pkt) >= 20 {
						if err := h.tun.Write(pkt); err != nil {
							h.debugf("tun write: %v", err)
						}
					} else {
						h.debugf("reassembled packet too short (%d)", len(pkt))
					}
				}
			}
		}
	} else if err != nil {
		h.debugf("bad b32 payload: %v", err)
	}

	// ---- downstream: pack as many queued packets as the reply can carry ----
	budget := h.payloadBudget(q)
	pkts, remaining := s.drainUpTo(budget)
	payload := make([]byte, 0, 3+budget)
	flags := uint8(0)
	if remaining > 0 {
		flags |= flagDown
	}
	payload = appendDownHdr(payload, s.nextSeq(), flags)
	for _, p := range pkts {
		payload = append(payload, p...)
	}
	s.DownBytes.Add(uint64(len(payload)))
	s.DownPkts.Add(uint64(len(pkts)))
	if h.cfg.Debug && len(pkts) > 0 {
		h.debugf("down: %d pkt(s) %dB -> reply %dB (queue left %dB)", len(pkts), len(payload), h.replySize(q, payload), remaining)
	}
	return buildDNSResponse(q, []dnsAnswer{{Type: 16, Data: txtRdata(payload), TTL: 0}}, 0)
}

// replySize computes the exact DNS message size for a given payload.
func (h *Handler) replySize(q *dnsQuery, payload []byte) int {
	rdata := len(payload) + (len(payload)+254)/255 // TXT length prefixes
	return 12 + wireLen(q.Q.Name) + 4 + 2 + 10 + rdata + 11
}

// payloadBudget returns how many payload bytes fit in the reply while staying
// under both the client's advertised EDNS0 buffer and the server's cap.
func (h *Handler) payloadBudget(q *dnsQuery) int {
	limit := int(q.EdnsUDPSize)
	if limit < 512 {
		limit = 512
	}
	if limit > h.cfg.MaxUDP {
		limit = h.cfg.MaxUDP
	}
	fixed := 12 + wireLen(q.Q.Name) + 4 + 2 + 10 + 11 + 3 // + downstream header
	avail := limit - fixed
	if avail <= 0 {
		return 0
	}
	// subtract TXT length-prefix bytes
	for {
		need := avail + (avail+254)/255
		if need <= limit-fixed+3 {
			break
		}
		avail -= (avail + 254) / 255
		if avail <= 0 {
			return 0
		}
	}
	return avail
}

// ---------------------------------------------------------------------------
// response-size probe (<bytes>.probe.<zone>) - the client uses it to discover
// the largest reply its resolver will actually deliver.
// ---------------------------------------------------------------------------

func (h *Handler) sizeProbe(q *dnsQuery, n int, tr transportKind) []byte {
	if n < 64 {
		n = 64
	}
	if n > 8000 {
		n = 8000
	}
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}
	resp := buildDNSResponse(q, []dnsAnswer{{Type: 16, Data: txtRdata(payload), TTL: 0}}, 0)
	// behave like a real authoritative server: if the answer does not fit the
	// requester's UDP buffer, set TC so it retries over TCP.
	if tr == trUDP {
		limit := 512
		if q.EdnsPresent {
			limit = int(q.EdnsUDPSize)
		}
		if limit < 512 {
			limit = 512
		}
		if len(resp) > limit {
			resp = buildDNSResponse(q, nil, 0)
			resp[2] |= 0x02 // TC
		}
	}
	h.debugf("sizeProbe: n=%d resp=%d tr=%d", n, len(resp), tr)
	return resp
}

// stripDomain removes the zone labels from the end of a label list.
func stripDomain(labels []string, domain string) ([]string, bool) {
	dl := strings.Split(strings.ToLower(domain), ".")
	if len(labels) < len(dl) {
		return nil, false
	}
	for i := 0; i < len(dl); i++ {
		if labels[len(labels)-1-i] != dl[len(dl)-1-i] {
			return nil, false
		}
	}
	return labels[:len(labels)-len(dl)], true
}
