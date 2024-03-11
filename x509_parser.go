// Slightly modified version of the x509 package from the Go standard library
// to parse Brainpool certificates.
//
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package healthcard

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func ParseCertificate(der []byte) (*x509.Certificate, error) {
	// try parsing the certificate with the standard library
	cert, err := x509.ParseCertificate(der)
	if err == nil {
		return cert, nil
	}
	// down the brainpool drain
	cert = &x509.Certificate{}

	input := cryptobyte.String(der)
	// we read the SEQUENCE including length and tag bytes so that
	// we can populate Certificate.Raw, before unwrapping the
	// SEQUENCE so it can be operated on
	if !input.ReadASN1Element(&input, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed certificate")
	}
	cert.Raw = input
	if !input.ReadASN1(&input, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed certificate")
	}

	var tbs cryptobyte.String
	// do the same trick again as above to extract the raw
	// bytes for Certificate.RawTBSCertificate
	if !input.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs certificate")
	}
	cert.RawTBSCertificate = tbs
	if !tbs.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs certificate")
	}

	if !tbs.ReadOptionalASN1Integer(&cert.Version, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), 0) {
		return nil, errors.New("x509: malformed version")
	}
	if cert.Version < 0 {
		return nil, errors.New("x509: malformed version")
	}
	// for backwards compat reasons Version is one-indexed,
	// rather than zero-indexed as defined in 5280
	cert.Version++
	if cert.Version > 3 {
		return nil, errors.New("x509: invalid version")
	}

	serial := new(big.Int)
	if !tbs.ReadASN1Integer(serial) {
		return nil, errors.New("x509: malformed serial number")
	}
	// we ignore the presence of negative serial numbers because
	// of their prevalence, despite them being invalid
	// TODO(rolandshoemaker): revisit this decision, there are currently
	// only 10 trusted certificates with negative serial numbers
	// according to censys.io.
	cert.SerialNumber = serial

	var sigAISeq cryptobyte.String
	if !tbs.ReadASN1(&sigAISeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed signature algorithm identifier")
	}
	// Before parsing the inner algorithm identifier, extract
	// the outer algorithm identifier and make sure that they
	// match.
	var outerSigAISeq cryptobyte.String
	if !input.ReadASN1(&outerSigAISeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed algorithm identifier")
	}
	if !bytes.Equal(outerSigAISeq, sigAISeq) {
		return nil, errors.New("x509: inner and outer signature algorithm identifiers don't match")
	}
	/*
		sigAI, err := parseAI(sigAISeq)
		if err != nil {
			return nil, err
		}
		cert.SignatureAlgorithm = getSignatureAlgorithmFromAI(sigAI)
	*/

	var issuerSeq cryptobyte.String
	if !tbs.ReadASN1Element(&issuerSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed issuer")
	}
	cert.RawIssuer = issuerSeq
	issuerRDNs, err := parseName(issuerSeq)
	if err != nil {
		return nil, err
	}
	cert.Issuer.FillFromRDNSequence(issuerRDNs)

	var validity cryptobyte.String
	if !tbs.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed validity")
	}
	cert.NotBefore, cert.NotAfter, err = parseValidity(validity)
	if err != nil {
		return nil, err
	}

	var subjectSeq cryptobyte.String
	if !tbs.ReadASN1Element(&subjectSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed issuer")
	}
	cert.RawSubject = subjectSeq
	subjectRDNs, err := parseName(subjectSeq)
	if err != nil {
		return nil, err
	}
	cert.Subject.FillFromRDNSequence(subjectRDNs)

	var spki cryptobyte.String
	if !tbs.ReadASN1Element(&spki, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed spki")
	}
	cert.RawSubjectPublicKeyInfo = spki
	if !spki.ReadASN1(&spki, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed spki")
	}
	var pkAISeq cryptobyte.String
	if !spki.ReadASN1(&pkAISeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed public key algorithm identifier")
	}
	/*
		pkAI, err := parseAI(pkAISeq)
		if err != nil {
			return nil, err
		}
			cert.PublicKeyAlgorithm = getPublicKeyAlgorithmFromOID(pkAI.Algorithm)
			var spk asn1.BitString
			if !spki.ReadASN1BitString(&spk) {
				return nil, errors.New("x509: malformed subjectPublicKey")
			}
			if cert.PublicKeyAlgorithm != UnknownPublicKeyAlgorithm {
				cert.PublicKey, err = parsePublicKey(&publicKeyInfo{
					Algorithm: pkAI,
					PublicKey: spk,
				})
				if err != nil {
					return nil, err
				}
			}
	*/

	if cert.Version > 1 {
		if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(1).ContextSpecific()) {
			return nil, errors.New("x509: malformed issuerUniqueID")
		}
		if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(2).ContextSpecific()) {
			return nil, errors.New("x509: malformed subjectUniqueID")
		}
		if cert.Version == 3 {
			var extensions cryptobyte.String
			var present bool
			if !tbs.ReadOptionalASN1(&extensions, &present, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
				return nil, errors.New("x509: malformed extensions")
			}
			if present {
				seenExts := make(map[string]bool)
				if !extensions.ReadASN1(&extensions, cryptobyte_asn1.SEQUENCE) {
					return nil, errors.New("x509: malformed extensions")
				}
				for !extensions.Empty() {
					var extension cryptobyte.String
					if !extensions.ReadASN1(&extension, cryptobyte_asn1.SEQUENCE) {
						return nil, errors.New("x509: malformed extension")
					}
					ext, err := parseExtension(extension)
					if err != nil {
						return nil, err
					}
					oidStr := ext.Id.String()
					if seenExts[oidStr] {
						return nil, errors.New("x509: certificate contains duplicate extensions")
					}
					seenExts[oidStr] = true
					cert.Extensions = append(cert.Extensions, ext)
				}
				/*
					err = processExtensions(cert)
					if err != nil {
						return nil, err
					}
				*/
			}
		}
	}

	var signature asn1.BitString
	if !input.ReadASN1BitString(&signature) {
		return nil, errors.New("x509: malformed signature")
	}
	cert.Signature = signature.RightAlign()

	return cert, nil
}

func parseAI(der cryptobyte.String) (pkix.AlgorithmIdentifier, error) {
	ai := pkix.AlgorithmIdentifier{}
	if !der.ReadASN1ObjectIdentifier(&ai.Algorithm) {
		return ai, errors.New("x509: malformed OID")
	}
	if der.Empty() {
		return ai, nil
	}
	var params cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !der.ReadAnyASN1Element(&params, &tag) {
		return ai, errors.New("x509: malformed parameters")
	}
	ai.Parameters.Tag = int(tag)
	ai.Parameters.FullBytes = params
	return ai, nil
}

// parseName parses a DER encoded Name as defined in RFC 5280. We may
// want to export this function in the future for use in crypto/tls.
func parseName(raw cryptobyte.String) (*pkix.RDNSequence, error) {
	if !raw.ReadASN1(&raw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid RDNSequence")
	}

	var rdnSeq pkix.RDNSequence
	for !raw.Empty() {
		var rdnSet pkix.RelativeDistinguishedNameSET
		var set cryptobyte.String
		if !raw.ReadASN1(&set, cryptobyte_asn1.SET) {
			return nil, errors.New("x509: invalid RDNSequence")
		}
		for !set.Empty() {
			var atav cryptobyte.String
			if !set.ReadASN1(&atav, cryptobyte_asn1.SEQUENCE) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute")
			}
			var attr pkix.AttributeTypeAndValue
			if !atav.ReadASN1ObjectIdentifier(&attr.Type) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute type")
			}
			var rawValue cryptobyte.String
			var valueTag cryptobyte_asn1.Tag
			if !atav.ReadAnyASN1(&rawValue, &valueTag) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute value")
			}
			var err error
			attr.Value, err = parseASN1String(valueTag, rawValue)
			if err != nil {
				return nil, fmt.Errorf("x509: invalid RDNSequence: invalid attribute value: %s", err)
			}
			rdnSet = append(rdnSet, attr)
		}

		rdnSeq = append(rdnSeq, rdnSet)
	}

	return &rdnSeq, nil
}

// parseASN1String parses the ASN.1 string types T61String, PrintableString,
// UTF8String, BMPString, IA5String, and NumericString. This is mostly copied
// from the respective encoding/asn1.parse... methods, rather than just
// increasing the API surface of that package.
func parseASN1String(tag cryptobyte_asn1.Tag, value []byte) (string, error) {
	switch tag {
	case cryptobyte_asn1.T61String:
		return string(value), nil
	case cryptobyte_asn1.PrintableString:
		for _, b := range value {
			if !isPrintable(b) {
				return "", errors.New("invalid PrintableString")
			}
		}
		return string(value), nil
	case cryptobyte_asn1.UTF8String:
		if !utf8.Valid(value) {
			return "", errors.New("invalid UTF-8 string")
		}
		return string(value), nil
	case cryptobyte_asn1.Tag(asn1.TagBMPString):
		if len(value)%2 != 0 {
			return "", errors.New("invalid BMPString")
		}

		// Strip terminator if present.
		if l := len(value); l >= 2 && value[l-1] == 0 && value[l-2] == 0 {
			value = value[:l-2]
		}

		s := make([]uint16, 0, len(value)/2)
		for len(value) > 0 {
			s = append(s, uint16(value[0])<<8+uint16(value[1]))
			value = value[2:]
		}

		return string(utf16.Decode(s)), nil
	case cryptobyte_asn1.IA5String:
		s := string(value)
		if isIA5String(s) != nil {
			return "", errors.New("invalid IA5String")
		}
		return s, nil
	case cryptobyte_asn1.Tag(asn1.TagNumericString):
		for _, b := range value {
			if !('0' <= b && b <= '9' || b == ' ') {
				return "", errors.New("invalid NumericString")
			}
		}
		return string(value), nil
	}
	return "", fmt.Errorf("unsupported string type: %v", tag)
}

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

func parseValidity(der cryptobyte.String) (time.Time, time.Time, error) {
	notBefore, err := parseTime(&der)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := parseTime(&der)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	return notBefore, notAfter, nil
}

// isPrintable reports whether the given b is in the ASN.1 PrintableString set.
// This is a simplified version of encoding/asn1.isPrintable.
func isPrintable(b byte) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?' ||
		// This is technically not allowed in a PrintableString.
		// However, x509 certificates with wildcard strings don't
		// always use the correct string type so we permit it.
		b == '*' ||
		// This is not technically allowed either. However, not
		// only is it relatively common, but there are also a
		// handful of CA certificates that contain it. At least
		// one of which will not expire until 2027.
		b == '&'
}

func parseTime(der *cryptobyte.String) (time.Time, error) {
	var t time.Time
	switch {
	case der.PeekASN1Tag(cryptobyte_asn1.UTCTime):
		if !der.ReadASN1UTCTime(&t) {
			return t, errors.New("x509: malformed UTCTime")
		}
	case der.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime):
		if !der.ReadASN1GeneralizedTime(&t) {
			return t, errors.New("x509: malformed GeneralizedTime")
		}
	default:
		return t, errors.New("x509: unsupported time format")
	}
	return t, nil
}

func parseExtension(der cryptobyte.String) (pkix.Extension, error) {
	var ext pkix.Extension
	if !der.ReadASN1ObjectIdentifier(&ext.Id) {
		return ext, errors.New("x509: malformed extension OID field")
	}
	if der.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
		if !der.ReadASN1Boolean(&ext.Critical) {
			return ext, errors.New("x509: malformed extension critical field")
		}
	}
	var val cryptobyte.String
	if !der.ReadASN1(&val, cryptobyte_asn1.OCTET_STRING) {
		return ext, errors.New("x509: malformed extension value field")
	}
	ext.Value = val
	return ext, nil
}
