package healthcard_test

import (
	"log"
	"log/slog"
	"testing"

	"github.com/spilikin/healthcard"
)

func TestReadCard(t *testing.T) {
	// get a list of abailable PC/SC readers
	readers, err := healthcard.Readers()
	if err != nil {
		log.Fatal(err)
	}

	if len(readers) == 0 {
		log.Fatal("no readers found")
	}

	slog.Info("Available readers", "readers", readers)

	// open the first reader nd see if card is a eGK
	card, err := healthcard.Open(readers[0])
	if err != nil {
		log.Fatal(err)
	}

	slog.Info("Card", "cardType", card.MF.CardType)

	if card.MF.CardType != healthcard.CardTypeEGK {
		log.Fatal("not aGK")
	}

	// select the ESIGN application
	err = card.SelectDF(healthcard.DF_ESIGN.DF)
	if err != nil {
		log.Fatal(err)
	}

	// read AUT certificate (brainpoolP256r1)
	cert, err := card.ReadCertificate(healthcard.DF_ESIGN.EF_C_CH_AUT_E256)
	if err != nil {
		log.Fatal(err)
	}

	slog.Info("AUT certificate", "subject", cert.Subject, "issuer", cert.Issuer, "alg", cert.PublicKeyAlgorithm)

}
