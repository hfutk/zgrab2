package rdp

import (
        "encoding/binary"
        "io"
        "net"
        "testing"
)

func TestSelectedProtocolName(t *testing.T) {
        cases := []struct {
                mask uint32
                want string
        }{
                {protocolRDP, "standard_rdp"},
                {protocolSSL, "ssl"},
                {protocolHybrid, "hybrid"},
                {protocolSSL | protocolHybrid, "ssl+hybrid"}, // 0x03: modern Windows default (TLS + CredSSP/NLA)
                {protocolRDSTLS, "rdstls"},
                {protocolHybridEx, "hybrid_ex"},
                {protocolSSL | protocolHybrid | protocolHybridEx, "ssl+hybrid+hybrid_ex"},
                {protocolSSL | protocolRDSTLS, "ssl+rdstls"},
                {0x00000020, "unknown(0x20)"}, // reserved bit without any known bit
        }
        for _, tc := range cases {
                if got := selectedProtocolName(tc.mask); got != tc.want {
                        t.Errorf("selectedProtocolName(0x%x) = %q, want %q", tc.mask, got, tc.want)
                }
        }
}

func TestDecodeNegotiationFlags(t *testing.T) {
        none := decodeNegotiationFlags(0x00)
        if none.ExtendedClientDataSupported || none.DynvcGfxProtocolSupported ||
                none.RestrictedAdminModeSupported || none.RedirectedAuthModeSupported {
                t.Errorf("flags 0x00 must decode to all-false, got %+v", none)
        }
        all := decodeNegotiationFlags(negRspFlagExtendedClientData | negRspFlagDynvcGfx | negRspFlagRestrictedAdmin | negRspFlagRedirectedAuth)
        if !all.ExtendedClientDataSupported || !all.DynvcGfxProtocolSupported ||
                !all.RestrictedAdminModeSupported || !all.RedirectedAuthModeSupported {
                t.Errorf("flags 0x1b must decode to all-true, got %+v", all)
        }
}

// buildCC builds a TPKT + X.224 Connection Confirm with an RDP Negotiation
// Response selecting the given protocol mask (or a Negotiation Failure with
// the given code when fail is true).
func buildCC(selected uint32, flags byte, fail bool, failureCode uint32) []byte {
        negType := byte(typeRDPNegRsp)
        if fail {
                negType = typeRDPNegFailure
        }
        neg := []byte{negType, flags, 0x08, 0x00, 0, 0, 0, 0}
        if fail {
                binary.LittleEndian.PutUint32(neg[4:8], failureCode)
        } else {
                binary.LittleEndian.PutUint32(neg[4:8], selected)
        }
        // X.224 CC TPDU: LI, type|CDT, DST-REF, SRC-REF, class 0
        tpdu := append([]byte{byte(6 + len(neg)), x224TPDUConnectionConfirm, 0, 0, 0, 0, 0}, neg...)
        pktLen := 4 + len(tpdu) + 1 // TPKT + LI byte included in tpdu? LI counts the bytes after itself.
        // tpdu[0] (LI) covers everything after the LI byte: 6 fixed + neg
        total := 4 + 1 + int(tpdu[0])
        pkt := []byte{0x03, 0x00, byte(total >> 8), byte(total)}
        _ = pktLen
        return append(pkt, tpdu...)
}

func TestX224NegotiateResponse(t *testing.T) {
        cases := []struct {
                name            string
                selected        uint32
                flags           byte
                fail            bool
                failureCode     uint32
                wantSelected    uint32
                wantFlags       byte
                wantFailureCode uint32
        }{
                {name: "standard rdp", selected: 0, wantSelected: 0},
                {name: "tls only", selected: protocolSSL, flags: 0x01, wantSelected: protocolSSL, wantFlags: 0x01},
                {name: "tls+credsso mask 0x03", selected: protocolSSL | protocolHybrid, wantSelected: 0x03},
                {name: "hybrid_ex", selected: protocolHybridEx, wantSelected: protocolHybridEx},
                {name: "failure ssl required", fail: true, failureCode: 0x01, wantFailureCode: 0x01},
                {name: "failure hybrid required", fail: true, failureCode: 0x05, wantFailureCode: 0x05},
        }
        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        server, client := net.Pipe()
                        go func() {
                                defer server.Close()
                                // consume the client's Connection Request
                                buf := make([]byte, 256)
                                if _, err := server.Read(buf); err != nil && err != io.EOF {
                                        t.Errorf("server read: %v", err)
                                }
                                server.Write(buildCC(tc.selected, tc.flags, tc.fail, tc.failureCode))
                        }()

                        selected, flags, failureCode, err := x224Negotiate(client)
                        if err != nil {
                                t.Fatalf("x224Negotiate: %v", err)
                        }
                        if selected != tc.wantSelected {
                                t.Errorf("selectedProtocol = 0x%x, want 0x%x", selected, tc.wantSelected)
                        }
                        if flags != tc.wantFlags {
                                t.Errorf("flags = 0x%x, want 0x%x", flags, tc.wantFlags)
                        }
                        if failureCode != tc.wantFailureCode {
                                t.Errorf("failureCode = 0x%x, want 0x%x", failureCode, tc.wantFailureCode)
                        }
                        client.Close()
                })
        }
}

func TestX224NegotiateRejectsGarbage(t *testing.T) {
        server, client := net.Pipe()
        go func() {
                defer server.Close()
                buf := make([]byte, 256)
                server.Read(buf) // consume the Connection Request
                server.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")) // not a TPKT
        }()
        if _, _, _, err := x224Negotiate(client); err == nil {
                t.Fatal("expected error for non-TPKT response, got nil")
        }
        client.Close()
}
