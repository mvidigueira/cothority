package ocs

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"go.dedis.ch/cothority/v3/ocs/certs"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/protobuf"

	"go.dedis.ch/kyber/v3"
)

func (ocs CreateOCS) verifyAuth(policies []Policy) error {
	for _, p := range policies {
		if err := p.verifyCreate(ocs.Auth); err == nil {
			return nil
		}
	}
	return errors.New("no policy matches against the authorization")
}

func (op OCSProof) Verify() error {
	if len(op.Signatures) != len(op.Roster.List) {
		return errors.New("length of signatures is not equal to roster list length")
	}
	msg, err := op.Message()
	if err != nil {
		return certs.Erret(err)
	}
	for i, si := range op.Roster.List {
		err := schnorr.Verify(cothority.Suite, si.ServicePublic(ServiceName), msg, op.Signatures[i])
		if err != nil {
			return certs.Erret(err)
		}
	}
	return nil
}

func (op OCSProof) Message() ([]byte, error) {
	hash := sha256.New()
	hash.Write(op.OcsID)
	coc := CreateOCS{
		Roster:          op.Roster,
		PolicyReencrypt: op.PolicyReencrypt,
		PolicyReshare:   op.PolicyReshare,
	}
	buf, err := protobuf.Encode(&coc)
	if err != nil {
		return nil, certs.Erret(err)
	}
	hash.Write(buf)
	return hash.Sum(nil), nil
}

func (re Reshare) verify() error {
	return errors.New("not yet implemented")
}

func (ar AuthReencrypt) verify(p Policy, X, U kyber.Point) error {
	if ar.X509Cert != nil && p.X509Cert != nil {
		return ar.X509Cert.verify(p, X, U)
	}
	if ar.ByzCoin != nil && p.ByzCoin != nil {
		return ar.ByzCoin.verify(p, X, U)
	}
	return errors.New("no matching policy/auth found")
}

func (ar AuthReencrypt) Xc() (kyber.Point, error) {
	if ar.X509Cert != nil {
		return certs.GetPointFromCert(ar.X509Cert.Certificates[0], certs.EphemeralKeyOID)
	}
	if ar.ByzCoin != nil {
		return nil, errors.New("can't get ephemeral key from ByzCoin yet")
	}
	return nil, errors.New("need to have authentication for X509 or ByzCoin")
}

func (ar AuthReencrypt) U() (kyber.Point, error) {
	if ar.X509Cert != nil {
		return ar.X509Cert.U, nil
	}
	if ar.ByzCoin != nil {
		return nil, errors.New("can't get secret from ByzCoin yet")
	}
	return nil, errors.New("need to have authentication for X509 or ByzCoin")
}

func (arX509 AuthReencryptX509Cert) verify(p Policy, X, U kyber.Point) error {
	return certs.Erret(p.X509Cert.verify(arX509.Certificates, func(vo x509.VerifyOptions, cert *x509.Certificate) error {
		return certs.Verify(vo, cert, X, U)
	}))
}

func (arBC AuthReencryptByzCoin) verify(p Policy, X, U kyber.Point) error {
	return errors.New("not yet implemented")
}

func (p Policy) verifyCreate(auth AuthCreate) error {
	if p.X509Cert != nil {
		return p.X509Cert.verifyCreate(auth)
	}
	if p.ByzCoin != nil {
		return p.ByzCoin.verifyCreate(auth)
	}
	return errors.New("neither x509 nor byzcoin policy stored")
}

func (p509 PolicyX509Cert) verify(certBufs [][]byte, vf func(vo x509.VerifyOptions, cert *x509.Certificate) error) error {
	var certs []*x509.Certificate
	for _, certBuf := range certBufs {
		cert, err := x509.ParseCertificate(certBuf)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}
	count := 0
	for _, caBuf := range p509.CA {
		ca, err := x509.ParseCertificate(caBuf)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		opt := x509.VerifyOptions{Roots: roots}
		for _, cert := range certs {
			if vf(opt, cert) == nil {
				count++
				break
			}
		}
	}
	if count >= p509.Threshold {
		return nil
	}
	return errors.New("didn't reach threshold")
}

func (p509 PolicyX509Cert) verifyCreate(auth AuthCreate) error {
	return p509.verify(auth.X509Cert.Certificates, func(vo x509.VerifyOptions, cert *x509.Certificate) error {
		_, err := cert.Verify(vo)
		return err
	})
}

func (pBC PolicyByzCoin) verifyCreate(auth AuthCreate) error {
	return errors.New("not yet implemented")
}

func NewOCSID(X kyber.Point) (OCSID, error) {
	return X.MarshalBinary()
}

func (ocs OCSID) X() (kyber.Point, error) {
	X := cothority.Suite.Point()
	err := certs.Erret(X.UnmarshalBinary(ocs))
	return X, err
}
