package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"go.dedis.ch/onet/v3/log"

	"go.dedis.ch/kyber/v3"
)

// Helper functions to create x509-certificates.
//
//   CertNode - can be given as a CA for Reencryption and Resharing
//   +-> CertReencrypt - indicates who is allowed to reencrypt and gives the ephemeral key

// BCCert is used as a structure in testing - this is not secure enough to be used in production.
type BCCert struct {
	Private     *ecdsa.PrivateKey
	Certificate *x509.Certificate
}

// NewBCCert is the general method to create a certificate for testing.
func NewBCCert(cn string, dur time.Duration, kus x509.KeyUsage, isCA bool,
	eext []pkix.Extension, root *x509.Certificate, rootPriv *ecdsa.PrivateKey) BCCert {
	notBefore := time.Now()
	notAfter := notBefore.Add(dur)
	serialNumber := big.NewInt(int64(1))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              kus,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
		IsCA:                  isCA,
	}
	if eext != nil {
		template.ExtraExtensions = eext
	}
	bcc := BCCert{}
	var err error
	bcc.Private, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	log.ErrFatal(err)
	if root == nil {
		root = &template
		rootPriv = bcc.Private
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, root, &bcc.Private.PublicKey, rootPriv)
	log.ErrFatal(err)

	bcc.Certificate, err = x509.ParseCertificate(derBytes)
	log.ErrFatal(err)
	return bcc
}

// CADur is the duration for a CA - here artificially restricted to 24 hours, because it is for testing only.
var CADur = 24 * time.Hour

// NewBCCA creates a CA cert.
func NewBCCA(cn string) BCCert {
	return NewBCCert(cn, CADur, x509.KeyUsageCertSign|x509.KeyUsageDataEncipherment, true,
		nil, nil, nil)
}

// CreateSubCA creates a CA that is signed by the CA of the given bcc.
func (bcc BCCert) CreateSubCA(cn string) BCCert {
	return NewBCCert(cn, CADur, x509.KeyUsageCertSign|x509.KeyUsageDataEncipherment, true,
		nil, bcc.Certificate, bcc.Private)
}

// Sign is a general signing method that creates a new certificate, which is not a CA.
func (bcc BCCert) Sign(cn string, eext []pkix.Extension) BCCert {
	return NewBCCert(cn, time.Hour, x509.KeyUsageKeyEncipherment, false, eext, bcc.Certificate, bcc.Private)
}

// Reencrypt is a specific reencryption certificate created with extrafields that are used by Calypso.
func (bcc BCCert) Reencrypt(writeID []byte, ephemeralPublicKey kyber.Point) BCCert {
	writeIdExt := pkix.Extension{
		Id:       WriteIdOID,
		Critical: true,
		Value:    writeID,
	}

	ephemeralKeyExt := pkix.Extension{
		Id:       EphemeralKeyOID,
		Critical: true,
	}
	var err error
	ephemeralKeyExt.Value, err = ephemeralPublicKey.MarshalBinary()
	log.ErrFatal(err)

	return bcc.Sign("reencryt", []pkix.Extension{writeIdExt, ephemeralKeyExt})
}

// CreateOCS returns a certificate that can be used to authenticate for OCS creation.
func (bcc BCCert) CreateOCS() BCCert {
	return bcc.Sign("createOCS", nil)
}

// CreateCertCa is used for tests and returns a new private key, as well as a CA certificate.
func CreateCertCa() (caPrivKey *ecdsa.PrivateKey, cert *x509.Certificate, err error) {
	bcc := NewBCCA("ByzGen signer org1")
	return bcc.Private, bcc.Certificate, nil
}

// CreateCertReencrypt is used for tests and can create a certificate for a reencryption request.
func CreateCertReencrypt(caCert *x509.Certificate, caPrivKey *ecdsa.PrivateKey,
	writeID []byte, ephemeralPublicKey kyber.Point) (*x509.Certificate, error) {
	bcc := BCCert{Certificate: caCert, Private: caPrivKey}.Reencrypt(writeID, ephemeralPublicKey)
	return bcc.Certificate, nil
}
