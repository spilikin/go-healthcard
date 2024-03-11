package healthcard

import (
	"fmt"
	"strings"
)

type APDUHeader struct {
	Cla byte
	Ins byte
	P1  byte
	P2  byte
}

var DO_FCP = BerTag{0x62}
var DO_AID = BerTag{0x84}

func (a *APDUHeader) Bytes() []byte {
	return []byte{a.Cla, a.Ins, a.P1, a.P2}
}

func (a *APDUHeader) String() string {
	return fmt.Sprintf("%02X %02X %02X %02X", a.Cla, a.Ins, a.P1, a.P2)
}

var selectMF = APDUHeader{0x00, 0xA4, 0x04, 0x04}
var selectDF = APDUHeader{0x00, 0xA4, 0x04, 0x0C}

type APDU struct {
	Header APDUHeader
	Body   []byte
}

func (a *APDU) Bytes() []byte {
	return append(a.Header.Bytes(), a.Body...)
}

func (a *APDU) String() string {
	return fmt.Sprintf("%s %02X", a.Header.String(), a.Body)
}

// prettyHex returns a pretty-printed hex string of the given data.
// each byte is separated by a space.
func prettyHex(data []byte) string {
	var sb strings.Builder
	for ind, b := range data {
		sb.WriteString(fmt.Sprintf("%02X", b))
		if ind < len(data)-1 {
			sb.WriteString(" ")
		}
	}

	return sb.String()
}

type apduBuilder struct {
	apdu APDU
}

func (a *apduBuilder) header(header APDUHeader) {
	a.apdu.Header = header
	a.apdu.Body = make([]byte, 0)
}

func (a *apduBuilder) Body(body ...byte) *apduBuilder {
	a.apdu.Body = body
	return a
}

func (a *apduBuilder) RawBytes(b ...byte) *apduBuilder {
	a.apdu.Body = append(a.apdu.Body, b...)
	return a
}

func (a *apduBuilder) APDU() APDU {
	return a.apdu
}

func Command(header APDUHeader) *apduBuilder {
	apduBuilder := apduBuilder{}
	apduBuilder.header(header)
	return &apduBuilder
}
