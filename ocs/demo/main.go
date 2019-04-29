// Demo of how the new OCS service works from an outside, non-go-test caller. It does the following steps:
//  1. set up a root CA that is stored in the service as being allowed to create new OCS-instances
//  2. Create a new OCS-instance with a reencryption policy being set by a node-certificate
//  3. Encrypt a symmetric key to the OCS-instance public key
//  4. Ask the OCS-instance to re-encrypt the key to an ephemeral key
//  5. Decrypt the symmetric key
package main

import (
	"bytes"
	"os"

	"go.dedis.ch/onet/v3"

	"go.dedis.ch/cothority/v3/ocs/certs"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin/bcadmin/lib"
	"go.dedis.ch/cothority/v3/ocs"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3/log"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Please give a roster.toml as first parameter")
	}
	roster, err := lib.ReadRoster(os.Args[1])
	log.ErrFatal(err)

	log.Info("Starting rainy day scenario")
	rainyDay(roster)

	log.Info("Starting happy day scenario")
	happyDay(roster)
}

func happyDay(roster *onet.Roster) {
	log.Info("1. Creating createOCS cert and setting OCS-create policy")
	cl := ocs.NewClient()
	coPrivKey, coCert, err := certs.CreateCertCa()
	log.ErrFatal(err)
	for _, si := range roster.List {
		err = cl.AddPolicyCreateOCS(si, ocs.Policy{X509Cert: &ocs.PolicyX509Cert{
			CA:        [][]byte{coCert.Raw},
			Threshold: 1,
		}})
		log.ErrFatal(err)
	}

	log.Info("2.a) Creating node cert")
	nodePrivKey, nodeCert, err := certs.CreateCertCa()
	log.ErrFatal(err)

	px := ocs.Policy{
		X509Cert: &ocs.PolicyX509Cert{
			CA:        [][]byte{nodeCert.Raw},
			Threshold: 2,
		},
	}

	log.Info("2.b) Creating new OCS")
	_, createCert, err := certs.CreateCertNode(coCert, coPrivKey)
	log.ErrFatal(err)
	authCreate := ocs.AuthCreate{
		X509Cert: &ocs.AuthCreateX509Cert{
			Certificates: [][]byte{createCert.Raw},
		},
	}
	ocsID, err := cl.CreateOCS(*roster, authCreate, px, px)
	log.ErrFatal(err)
	log.Infof("New OCS created with ID: %x", ocsID)

	log.Info("2.c) Get proofs of all nodes")
	proof, err := cl.GetProofs(*roster, ocsID)
	log.ErrFatal(err)
	log.ErrFatal(proof.Verify())
	log.Info("Proof got verified successfully on nodes:")
	for i, sig := range proof.Signatures {
		log.Infof("Signature %d of %s: %x", i, proof.Roster.List[i].Address, sig)
	}

	log.Info("3.a) Creating secret key and encrypting it with the OCS-key")
	secret := []byte("ocs for everybody")
	X, err := ocsID.X()
	log.ErrFatal(err)
	U, C, err := certs.EncodeKey(cothority.Suite, X, secret)
	log.ErrFatal(err)

	log.Info("3.b) Creating 2 certificates for the re-encryption")
	ephemeralKeyPair := key.NewKeyPair(cothority.Suite)
	wid, err := certs.NewWriteID(X, U)
	log.ErrFatal(err)
	reencryptCert1, err := certs.CreateCertReencrypt(nodeCert, nodePrivKey, wid, ephemeralKeyPair.Public)
	log.ErrFatal(err)
	reencryptCert2, err := certs.CreateCertReencrypt(nodeCert, nodePrivKey, wid, ephemeralKeyPair.Public)
	log.ErrFatal(err)

	log.Info("4. Asking OCS to re-encrypt the secret to an ephemeral key")
	authRe := ocs.AuthReencrypt{
		Ephemeral: ephemeralKeyPair.Public,
		X509Cert: &ocs.AuthReencryptX509Cert{
			U:            U,
			Certificates: [][]byte{reencryptCert1.Raw, reencryptCert2.Raw},
		},
	}
	XhatEnc, err := cl.Reencrypt(*roster, ocsID, authRe)
	log.ErrFatal(err)

	log.Info("5. Decrypt the symmetric key")
	secretRec, err := certs.DecodeKey(cothority.Suite, X, C, XhatEnc, ephemeralKeyPair.Private)
	log.ErrFatal(err)
	if bytes.Compare(secret, secretRec) != 0 {
		log.Fatal("Recovered secret is not the same")
	}

	log.Info("Successfully re-encrypted the key")
}

func rainyDay(roster *onet.Roster) {
	log.Info("1. Creating createOCS cert and setting OCS-create policy")
	cl := ocs.NewClient()
	coPrivKey, coCert, err := certs.CreateCertCa()
	log.ErrFatal(err)
	for _, si := range roster.List {
		err = cl.AddPolicyCreateOCS(si, ocs.Policy{X509Cert: &ocs.PolicyX509Cert{
			CA:        [][]byte{coCert.Raw},
			Threshold: 1,
		}})
		log.ErrFatal(err)
	}

	log.Info("2.a) Creating node cert")
	nodePrivKey, nodeCert, err := certs.CreateCertCa()
	log.ErrFatal(err)

	px := ocs.Policy{
		X509Cert: &ocs.PolicyX509Cert{
			CA:        [][]byte{nodeCert.Raw},
			Threshold: 2,
		},
	}

	log.Info("2.b) Creating new OCS")
	log.Info("2.b.i) Sending wrong authentication")
	_, createCert, err := certs.CreateCertNode(nodeCert, nodePrivKey)
	log.ErrFatal(err)
	authCreate := ocs.AuthCreate{
		X509Cert: &ocs.AuthCreateX509Cert{
			Certificates: [][]byte{createCert.Raw},
		},
	}
	ocsID, err := cl.CreateOCS(*roster, authCreate, px, px)
	if err == nil {
		log.Fatal("A wrongly authorized cert should not be able to create an OCS")
	}

	log.Info("2.b.ii) Sending correct authentication")
	_, createCert, err = certs.CreateCertNode(coCert, coPrivKey)
	log.ErrFatal(err)
	authCreate.X509Cert.Certificates = [][]byte{createCert.Raw}
	ocsID, err = cl.CreateOCS(*roster, authCreate, px, px)
	log.ErrFatal(err)
	log.Infof("New OCS created with ID: %x", ocsID)

	log.Info("2.c) Get proofs of all nodes")
	proof, err := cl.GetProofs(*roster, ocsID)
	log.ErrFatal(err)
	log.ErrFatal(proof.Verify())
	log.Info("Proof got verified successfully on nodes:")
	for i, sig := range proof.Signatures {
		log.Infof("Signature %d of %s: %x", i, proof.Roster.List[i].Address, sig)
	}

	log.Info("3.a) Creating secret key and encrypting it with the OCS-key")
	secret := []byte("ocs for everybody")
	X, err := ocsID.X()
	log.ErrFatal(err)
	U, _, err := certs.EncodeKey(cothority.Suite, X, secret)
	log.ErrFatal(err)

	log.Info("3.b) Creating 2 certificates for the re-encryption")
	ephemeralKeyPair := key.NewKeyPair(cothority.Suite)
	wid, err := certs.NewWriteID(X, U)
	log.ErrFatal(err)
	reencryptCert1, err := certs.CreateCertReencrypt(nodeCert, nodePrivKey, wid, ephemeralKeyPair.Public)
	log.ErrFatal(err)

	log.Info("4. Asking OCS to re-encrypt the secret to an ephemeral key")
	log.Info("4.a) only 1 certificate")
	authRe := ocs.AuthReencrypt{
		Ephemeral: ephemeralKeyPair.Public,
		X509Cert: &ocs.AuthReencryptX509Cert{
			U:            U,
			Certificates: [][]byte{reencryptCert1.Raw},
		},
	}
	_, err = cl.Reencrypt(*roster, ocsID, authRe)
	if err == nil {
		log.Fatal("One certificate alone shouldn't be accepted with threshold == 2")
	}

	log.Info("4.b) twice the same certificate")
	authRe.X509Cert.Certificates = [][]byte{reencryptCert1.Raw, reencryptCert1.Raw}
	_, err = cl.Reencrypt(*roster, ocsID, authRe)
	if err == nil {
		log.Fatal("Twice the same certificate shouldn't be accepted with threshold == 2")
	}
}
