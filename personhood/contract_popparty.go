package personhood

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/sign/anon"
	"github.com/dedis/kyber/xof/blake2xs"
	"github.com/dedis/onet/log"
	"strings"

	"github.com/dedis/cothority"
	"github.com/dedis/cothority/byzcoin"
	"github.com/dedis/cothority/byzcoin/contracts"
	"github.com/dedis/cothority/darc"
	"github.com/dedis/onet/network"
	"github.com/dedis/protobuf"
)

// ContractPopPartyID represents a pop-party that can be in one of three states:
//   1 - configuration
//   2 - scanning
//   3 - finalized
var ContractPopPartyID = "popParty"

type ContractPopParty struct {
	byzcoin.BasicContract
	PopPartyStruct
}

func ContractPopPartyFromBytes(in []byte) (byzcoin.Contract, error) {
	c := &ContractPopParty{}
	err := protobuf.DecodeWithConstructors(in, &c.PopPartyStruct, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return nil, errors.New("couldn't unmarshal existing PopPartyStruct: " + err.Error())
	}
	return c, nil
}

func (c ContractPopParty) VerifyInstruction(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, ctxHash []byte) error {
	if inst.GetType() == byzcoin.InvokeType && inst.Invoke.Command == "mine" {
		log.Lvl2("not verifying darc for mining")
		return nil
	}
	return c.BasicContract.VerifyInstruction(rst, inst, ctxHash)
}

func (c ContractPopParty) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (scs []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	descBuf := inst.Spawn.Args.Search("description")
	if descBuf == nil {
		return nil, nil, errors.New("need description argument")
	}
	darcID := inst.Spawn.Args.Search("darcID")
	if darcID == nil {
		return nil, nil, errors.New("no darcID argument")
	}
	c.State = 1

	err = protobuf.DecodeWithConstructors(descBuf, &c.Description, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return nil, nil, errors.New("couldn't unmarshal the description: " + err.Error())
	}

	value, _, _, _, err := rst.GetValues(darcID)
	if err != nil {
		return nil, nil, errors.New("couldn't get darc in charge: " + err.Error())
	}
	d, err := darc.NewFromProtobuf(value)
	if err != nil {
		return nil, nil, errors.New("couldn't get darc: " + err.Error())
	}
	expr := d.Rules.Get("invoke:finalize")
	c.Organizers = len(strings.Split(string(expr), "|"))

	miningRewardBuf := inst.Spawn.Args.Search("miningReward")
	if miningRewardBuf == nil {
		return nil, nil, errors.New("no miningReward argument")
	}
	c.MiningReward = binary.LittleEndian.Uint64(miningRewardBuf)

	ppiBuf, err := protobuf.Encode(&c.PopPartyStruct)
	if err != nil {
		return nil, nil, errors.New("couldn't marshal PopPartyStruct: " + err.Error())
	}

	scs = byzcoin.StateChanges{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), ContractPopPartyID, ppiBuf, darcID),
	}
	return
}

type suite_blake2s struct {
	edwards25519.SuiteEd25519
}

func (sb suite_blake2s) XOF(key []byte) kyber.XOF {
	return blake2xs.New(key)
}

func (c *ContractPopParty) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (scs []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return nil, nil, errors.New("couldn't get instance data: " + err.Error())
	}

	switch inst.Invoke.Command {
	case "barrier":
		if c.State != 1 {
			return nil, nil, fmt.Errorf("can only start barrier point when in configuration mode")
		}
		c.State = 2

	case "finalize":
		if c.State != 2 {
			return nil, nil, fmt.Errorf("can only finalize when barrier point is passed")
		}

		attBuf := inst.Invoke.Args.Search("attendees")
		if attBuf == nil {
			return nil, nil, errors.New("missing argument: attendees")
		}
		var atts Attendees
		err = protobuf.DecodeWithConstructors(attBuf, &atts, network.DefaultConstructors(cothority.Suite))
		log.Lvl2("Adding attendees:", atts.Keys)

		alreadySigned := false
		orgSigner := inst.Signatures[0].Signer.String()
		for _, f := range c.Finalizations {
			if f == orgSigner {
				alreadySigned = true
				log.Print("this organizer already sent a finalization - resetting list of attendees")
				break
			}
		}

		if len(c.Finalizations) == 0 || alreadySigned {
			// Store first proposition of list of attendees or reset if the same
			// organizer submits again
			c.Attendees = atts
			c.Finalizations = []string{orgSigner}
			log.Print("resetting list of attendees")
		} else {
			// Check if it is the same set of attendees or not
			same := len(c.Attendees.Keys) == len(atts.Keys)
			if same {
				for i, att := range c.Attendees.Keys {
					if !att.Equal(atts.Keys[i]) {
						same = false
					}
				}
			}
			if same {
				log.Print("one more finalization")
				c.Finalizations = append(c.Finalizations, orgSigner)
			} else {
				log.Print("not the same list of attendees - resetting")
				c.Attendees = atts
				c.Finalizations = []string{orgSigner}
			}
		}
		if len(c.Finalizations) == c.Organizers {
			log.Lvlf2("Successfully finalized party %s / %x", c.Description.Name, inst.InstanceID[:])
			c.State = 3
		}

	case "addParty":
		if c.State != 3 {
			return nil, nil, errors.New("cannot add party when party is not finalized")
		}
		return nil, nil, errors.New("not yet implemented")

	case "mine":
		if c.State != 3 {
			return nil, nil, errors.New("cannot mine when party is not finalized")
		}
		lrs := inst.Invoke.Args.Search("lrs")
		if lrs == nil {
			return nil, nil, errors.New("need lrs argument")
		}
		tag, err := anon.Verify(&suite_blake2s{}, []byte("mine"), c.Attendees.Keys, inst.InstanceID[:], lrs)
		if err != nil {
			return nil, nil, errors.New("error while verifying signature: " + err.Error())
		}
		for _, t := range c.Miners {
			if bytes.Compare(t.Tag, tag) == 0 {
				return nil, nil, errors.New("this attendee already mined")
			}
		}
		c.Miners = append(c.Miners, LRSTag{Tag: tag})

		var coin byzcoin.Coin
		var coinDarc darc.ID
		coinAction := byzcoin.Update
		coinIID := inst.Invoke.Args.Search("coinIID")
		if coinIID == nil {
			newDarcBuf := inst.Invoke.Args.Search("newDarc")
			if newDarcBuf == nil {
				return nil, nil, errors.New("need either coinIID or newDarc argument")
			}
			newDarc, err := darc.NewFromProtobuf(newDarcBuf)
			if err != nil {
				return nil, nil, errors.New("couldn't unmarshal darc: " + err.Error())
			}
			// Creating new darc for new user
			log.Lvlf2("Creating new darc %x for user", newDarc.GetBaseID())
			scs = append(scs, byzcoin.NewStateChange(byzcoin.Create,
				byzcoin.NewInstanceID(newDarc.GetBaseID()), byzcoin.ContractDarcID,
				newDarcBuf, darcID))
			coinAction = byzcoin.Create
			h := sha256.New()
			h.Write([]byte("coin"))
			h.Write(newDarc.GetBaseID())
			coinIID = h.Sum(nil)
			coinDarc = newDarc.GetBaseID()
			log.Lvlf2("Creating new coin %x for user", coinIID)
			coin.Name = byzcoin.NewInstanceID([]byte("SpawnerCoin"))
		} else {
			var cid string
			var coinBuf []byte
			coinBuf, _, cid, coinDarc, err = rst.GetValues(coinIID)
			if cid != contracts.ContractCoinID {
				return nil, nil, errors.New("coinIID is not a coin contract")
			}
			err = protobuf.Decode(coinBuf, &coin)
			if err != nil {
				return nil, nil, errors.New("couldn't unmarshal coin: " + err.Error())
			}
		}
		err = coin.SafeAdd(c.MiningReward)
		if err != nil {
			return nil, nil, errors.New("couldn't add mining reward: " + err.Error())
		}
		coinBuf, err := protobuf.Encode(&coin)
		if err != nil {
			return nil, nil, errors.New("couldn't encode coin: " + err.Error())
		}
		scs = append(scs, byzcoin.NewStateChange(coinAction,
			byzcoin.NewInstanceID(coinIID),
			contracts.ContractCoinID, coinBuf, coinDarc))

	default:
		return nil, nil, errors.New("unknown command: " + inst.Invoke.Command)
	}

	// Storing new version of PopPartyStruct
	ppiBuf, err := protobuf.Encode(&c.PopPartyStruct)
	if err != nil {
		return nil, nil, errors.New("couldn't marshal PopPartyStruct: " + err.Error())
	}

	// Update existing party structure
	scs = append(scs, byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractPopPartyID, ppiBuf, darcID))

	return scs, coins, nil
}
