package personhood

import (
	"errors"
	"fmt"
	"github.com/dedis/onet/log"
	"strings"

	"github.com/dedis/cothority"
	"github.com/dedis/cothority/byzcoin"
	"github.com/dedis/cothority/byzcoin/contracts"
	"github.com/dedis/cothority/darc"
	"github.com/dedis/onet/network"
	"github.com/dedis/protobuf"
)

// ContractPopParty represents a pop-party that can be in one of three states:
//   1 - configuration
//   2 - scanning
//   3 - finalized
var ContractPopParty = "popParty"

type contract struct {
	byzcoin.BasicContract
	PopPartyStruct
}

func contractPopPartyFromBytes(in []byte) (byzcoin.Contract, error) {
	c := &contract{}
	err := protobuf.DecodeWithConstructors(in, &c.PopPartyStruct, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return nil, errors.New("couldn't unmarshal existing PopPartyStruct: " + err.Error())
	}
	return c, nil
}

func (c *contract) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (scs []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
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

	ppiBuf, err := protobuf.Encode(&c.PopPartyStruct)
	if err != nil {
		return nil, nil, errors.New("couldn't marshal PopPartyStruct: " + err.Error())
	}

	scs = byzcoin.StateChanges{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), inst.Spawn.ContractID, ppiBuf, darc.ID(inst.InstanceID[:])),
	}
	return
}

func (c *contract) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (scs []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
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
		if inst.Signatures[0].Signer.Darc == nil {
			return nil, nil, errors.New("only darc-signers allowed for finalizing")
		}

		attBuf := inst.Invoke.Args.Search("attendees")
		if attBuf == nil {
			return nil, nil, errors.New("missing argument: attendees")
		}
		var atts Attendees
		err = protobuf.DecodeWithConstructors(attBuf, &atts, network.DefaultConstructors(cothority.Suite))

		alreadySigned := false
		orgDarc := inst.Signatures[0].Signer.Darc.ID
		for _, f := range c.Finalizations {
			if f.Equal(orgDarc) {
				alreadySigned = true
				break
			}
		}

		if len(c.Finalizations) == 0 || alreadySigned {
			// Store first proposition of list of attendees or reset if the same
			// organizer submits again
			c.Attendees = atts
			c.Finalizations = []darc.ID{orgDarc}
		} else {
			// Check if it is the same set of attendees or not
			same := true
			for i, att := range c.Attendees.Keys {
				if !att.Equal(atts.Keys[i]) {
					same = false
				}
			}
			if same {
				c.Finalizations = append(c.Finalizations, orgDarc)
				if len(c.Finalizations) == c.Organizers{
					log.Lvl2("Successfully finalized party %s / %x", c.Description.Name, inst.InstanceID[:])
					c.State = 3
				}
			} else {
				c.Attendees = atts
				c.Finalizations = []darc.ID{orgDarc}
			}
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

		coinIID := inst.Invoke.Args.Search("coinIID")
		if coinIID == nil {
			return nil, nil, errors.New("need coinIID argument")
		}
		coinBuf, _, cid, coinDarc, err := rst.GetValues(coinIID)
		if cid != contracts.ContractCoinID {
			return nil, nil, errors.New("coinIID is not a coin contract")
		}
		var coin byzcoin.Coin
		err = protobuf.Decode(coinBuf, &coin)
		if err != nil {
			return nil, nil, errors.New("couldn't unmarshal coin: " + err.Error())
		}
		err = coin.SafeAdd(c.MiningReward)
		if err != nil {
			return nil, nil, errors.New("couldn't add mining reward: " + err.Error())
		}
		coinBuf, err = protobuf.Encode(coin)
		scs = append(scs, byzcoin.NewStateChange(byzcoin.Update,
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
	scs = append(scs, byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractPopParty, ppiBuf, darcID))

	return scs, coins, nil
}
