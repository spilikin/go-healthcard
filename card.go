package healthcard

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/spilikin/go-brainpool"
	"github.com/spilikin/healthcard/pcsc"
)

type Card struct {
	sc *pcsc.Smartcard
	MF *MasterFile
}

var Readers = pcsc.Readers

func Open(reader string) (*Card, error) {
	sc, err := pcsc.Open(reader)
	if err != nil {
		return nil, fmt.Errorf("opening pcsc reader: %w", err)
	}

	return NewCard(sc)
}

func NewCard(sc *pcsc.Smartcard) (*Card, error) {
	cmdSelectMF := Command(selectMF).Body(0x00, 0x00, 0x00).APDU()
	slog.Info("Select MF", "cmd", prettyHex(cmdSelectMF.Bytes()))
	resp, err := sc.Transmit(cmdSelectMF.Bytes())
	if err != nil {
		return nil, fmt.Errorf("transmitting select MF command: %w", err)
	}

	slog.Info("Response", "resp", prettyHex(resp))

	tlvs, err := ParseTLV(resp)
	if err != nil {
		return nil, fmt.Errorf("parsing select MF response: %w", err)
	}

	tlv := tlvs.FindFirstWithTag(DO_FCP)
	if tlv == nil {
		return nil, fmt.Errorf("no AID tag found")
	}
	aidTlv := tlv.FirstChild(DO_AID)

	var masterFile *MasterFile
	for _, mf := range MasterFiles {
		if bytes.Equal(aidTlv.Value, mf.ApplicationIdentifier) {
			masterFile = &mf
			break
		}
	}

	if masterFile == nil {
		return nil, fmt.Errorf("unknown application identifier: %s", prettyHex(aidTlv.Value))
	}

	return &Card{sc: sc, MF: masterFile}, nil
}

func (c *Card) Close() error {
	return c.sc.Close()
}

func (c *Card) SelectDF(df DedicatedFile) error {
	apdu := Command(selectDF).
		RawBytes(byte(len(df.ApplicationIdentifier))).
		RawBytes(df.ApplicationIdentifier...).
		APDU()
	slog.Info("Select DF", "df", df.Name, "apdu", prettyHex(apdu.Bytes()))
	resp, err := c.sc.Transmit(apdu.Bytes())
	if err != nil {
		return fmt.Errorf("transmitting select DF command: %w", err)
	}

	slog.Info("Response", "resp", prettyHex(resp))

	return nil
}

func (c *Card) ReadTransparentEF(ef ElementaryFile) ([]byte, error) {
	apdu := Command(APDUHeader{0x00, 0xB0, 0x80 + ef.ShortIdentifier, 0x00}).
		RawBytes(0x00, 0x00, 0x00).
		APDU()
	slog.Info("Read EF", "apdu", prettyHex(apdu.Bytes()))
	resp, err := c.sc.Transmit(apdu.Bytes())
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Card) ReadCertificate(ef ElementaryFile) (x509.Certificate, error) {
	certBytes, err := c.ReadTransparentEF(ef)
	if err != nil {
		return x509.Certificate{}, err
	}

	cert, err := brainpool.ParseCertificate(certBytes)
	if err != nil {
		return x509.Certificate{}, fmt.Errorf("parsing certificate: %w", err)
	}

	return *cert, nil
}
