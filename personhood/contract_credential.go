package personhood

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/dedis/kyber/sign/schnorr"

	"github.com/dedis/cothority"

	"github.com/dedis/cothority/byzcoin"
	"github.com/dedis/cothority/darc"
	"github.com/dedis/onet/log"
	"github.com/dedis/protobuf"
)

// ContractCredentialID denotes a contract that can spawn new identities.
var ContractCredentialID = "credential"

func ContractCredentialFromBytes(in []byte) (byzcoin.Contract, error) {
	c := &ContractCredential{}
	err := protobuf.Decode(in, &c.CredentialStruct)
	if err != nil {
		return nil, errors.New("couldn't unmarshal instance data: " + err.Error())
	}
	return c, nil
}

type ContractCredential struct {
	byzcoin.BasicContract
	CredentialStruct
}

func (c ContractCredential) VerifyInstruction(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, ctxHash []byte) error {
	if inst.Invoke != nil && inst.Invoke.Command == "recover" {
		return nil
	}
	return c.BasicContract.VerifyInstruction(rst, inst, ctxHash)
}

func (c *ContractCredential) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	// Spawn creates a new credential as a separate instance.
	ca := inst.DeriveID("")
	if caBuf := inst.Spawn.Args.Search("instID"); caBuf != nil {
		ca = byzcoin.NewInstanceID(caBuf)
	}
	if darcIDBuf := inst.Spawn.Args.Search("darcIDBuf"); darcIDBuf != nil {
		darcID = darc.ID(darcIDBuf)
	}
	log.Lvlf3("Spawning Credential to %x", ca.Slice())
	var ciBuf []byte
	if ciBuf = inst.Spawn.Args.Search("credential"); ciBuf == nil {
		ciBuf, err = protobuf.Encode(&c.CredentialStruct)
		if err != nil {
			return nil, nil, errors.New("couldn't encode CredentialInstance: " + err.Error())
		}
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, ca, ContractCredentialID, ciBuf, darcID),
	}
	return
}

func (c *ContractCredential) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	switch inst.Invoke.Command {
	case "update":
		// update overwrites the credential information
		credBuf := inst.Invoke.Args.Search("credential")
		err = protobuf.Decode(credBuf, &c.CredentialStruct)
		if err != nil {
			return nil, nil, errors.New("got wrong credential data: " + err.Error())
		}

		sc = append(sc, byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID,
			ContractCredentialID, credBuf, darcID))

	case "recover":
		// "recover" checks if enough signatures are present to change the 'evolve' and 'sign' rule
		// of the darc attached to the credential.
		sigBuf := inst.Invoke.Args.Search("signatures")
		if len(sigBuf) == 0 || len(sigBuf)%96 != 0 {
			return nil, nil, errors.New("wrong signatures argument")
		}
		pubBuf := inst.Invoke.Args.Search("public")
		if len(pubBuf) != 32 {
			return nil, nil, errors.New("wrong 'public' argument")
		}
		public := cothority.Suite.Point()
		err = public.UnmarshalBinary(pubBuf)
		if err != nil {
			return
		}
		d, err := getDarc(rst, darcID)
		if err != nil {
			return nil, nil, err
		}
		var trusteesDarc []*darc.Darc
		var threshold uint32
		for _, cred := range c.Credentials {
			if cred.Name == "recover" {
				for _, att := range cred.Attributes {
					switch att.Name {
					case "threshold":
						threshold = binary.LittleEndian.Uint32(att.Value)
					case "trustees":
						for t := 0; t < len(att.Value); t += 32 {
							trusteeDarc, err := getDarcFromCredIID(rst, att.Value[t:t+32])
							if err != nil {
								return nil, nil, err
							}
							trusteesDarc = append(trusteesDarc, trusteeDarc)
						}
					default:
						return nil, nil, errors.New("unknown recover attribute: " + att.Name)
					}
				}
				break
			}
		}
		if threshold == 0 || len(trusteesDarc) == 0 {
			return nil, nil, errors.New("no threshold or no trustee found")
		}
		var valid uint32
		msg := append(inst.InstanceID.Slice(), pubBuf...)
		darcVersion := make([]byte, 8)
		binary.LittleEndian.PutUint64(darcVersion, d.Version)
		msg = append(msg, darcVersion...)
		for signer := 0; signer < len(sigBuf); signer += 96 {
			pubBuf := sigBuf[signer : signer+32]
			sig := sigBuf[signer+32 : signer+96]
			pub := cothority.Suite.Point()
			err = pub.UnmarshalBinary(pubBuf)
			if err != nil {
				return nil, nil, err
			}
			pubStr := darc.NewIdentityEd25519(pub).String()
			if err = schnorr.Verify(cothority.Suite, pub, msg, sig); err == nil {
				for _, trusteeDarc := range trusteesDarc {
					if err := checkDarcRule(rst, trusteeDarc, pubStr); err == nil {
						valid++
						break
					}
				}
			} else {
				log.Warn("Got invalid signature in recovery for public key", pubStr)
			}
		}
		if valid < threshold {
			return nil, nil, errors.New("didn't reach threshold for recovery")
		}
	default:
		err = errors.New("credential contract can only 'update'")
		return
	}
	return
}

func (c *ContractCredential) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	sc = byzcoin.StateChanges{
		byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractCredentialID, nil, darcID),
	}
	return
}

func getDarc(rst byzcoin.ReadOnlyStateTrie, darcID darc.ID) (*darc.Darc, error) {
	darcBuf, _, cid, _, err := rst.GetValues(darcID)
	if err != nil {
		return nil, err
	}
	if cid != byzcoin.ContractDarcID {
		return nil, errors.New("this is not a darc-id")
	}
	return darc.NewFromProtobuf(darcBuf)
}

func getDarcFromCredIID(rst byzcoin.ReadOnlyStateTrie, credIID []byte) (*darc.Darc, error) {
	_, _, cid, darcID, err := rst.GetValues(credIID)
	if err != nil {
		return nil, err
	}
	if cid != ContractCredentialID {
		return nil, errors.New("not a credential instance")
	}
	return getDarc(rst, darcID)
}

func checkDarcRule(rst byzcoin.ReadOnlyStateTrie, d *darc.Darc, id string) error {
	getDarc := func(str string, latest bool) *darc.Darc {
		if len(str) < 5 || string(str[0:5]) != "darc:" {
			return nil
		}
		darcID, err := hex.DecodeString(str[5:])
		if err != nil {
			return nil
		}
		d, err := byzcoin.LoadDarcFromTrie(rst, darcID)
		if err != nil {
			return nil
		}
		return d
	}
	return darc.EvalExpr(d.Rules.Get(darc.Action("_sign")), getDarc, id)
}
