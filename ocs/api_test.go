package ocs

import (
	"testing"

	"go.dedis.ch/cothority/v3/ocs/certs"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/util/key"

	"go.dedis.ch/onet/v3/log"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/onet/v3"
)

// Creates an OCS and checks that all nodes have the same view of the OCS.
func TestClient_GetProofs(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()
	nbrNodes := 5
	_, roster, _ := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes, true)

	_, caCert, err := certs.CreateCertCa()
	require.NoError(t, err)

	px := Policy{
		X509Cert: &PolicyX509Cert{
			CA:        [][]byte{caCert.Raw},
			Threshold: 1,
		},
	}

	cl := NewClient()
	_, createCert, err := certs.CreateCertCa()
	authCreate := AuthCreate{
		X509Cert: &AuthCreateX509Cert{
			Certificates: [][]byte{createCert.Raw},
		},
	}
	oid, err := cl.CreateOCS(*roster, authCreate, px, px)
	require.NoError(t, err)

	op, err := cl.GetProofs(*roster, oid)
	require.NoError(t, op.Verify())
	require.Equal(t, len(op.Signatures), len(roster.List))
}

// Asks OCS for a reencryption of a secret
func TestClient_Reencrypt(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()
	nbrNodes := 5
	_, roster, _ := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes, true)

	caPrivKey, caCert, err := certs.CreateCertCa()
	require.NoError(t, err)
	log.Lvl5(caPrivKey)

	px := Policy{
		X509Cert: &PolicyX509Cert{
			CA:        [][]byte{caCert.Raw},
			Threshold: 1,
		},
	}

	cl := NewClient()
	var oid OCSID
	_, createCert, err := certs.CreateCertCa()
	authCreate := AuthCreate{
		X509Cert: &AuthCreateX509Cert{
			Certificates: [][]byte{createCert.Raw},
		},
	}
	for i := 0; i < 10; i++ {
		oid, err = cl.CreateOCS(*roster, authCreate, px, px)
		require.NoError(t, err)
	}

	secret := []byte("ocs for everybody")
	X, err := oid.X()
	require.NoError(t, err)
	U, C, err := certs.EncodeKey(cothority.Suite, X, secret)
	require.NoError(t, err)

	kp := key.NewKeyPair(cothority.Suite)
	wid, err := certs.NewWriteID(X, U)
	require.NoError(t, err)
	reencryptCert, err := certs.CreateCertReencrypt(caCert, caPrivKey, wid, kp.Public)
	require.NoError(t, err)
	auth := AuthReencrypt{
		Ephemeral: kp.Public,
		X509Cert: &AuthReencryptX509Cert{
			U:            U,
			Certificates: [][]byte{reencryptCert.Raw},
		},
	}
	for i := 0; i < 10; i++ {
		XhatEnc, err := cl.Reencrypt(*roster, oid, auth)
		require.NoError(t, err)
		secretRec, err := certs.DecodeKey(cothority.Suite, X, C, XhatEnc, kp.Private)
		require.NoError(t, err)
		require.Equal(t, secret, secretRec)
	}
}
