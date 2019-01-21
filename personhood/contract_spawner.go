package personhood

import (
	"crypto/sha256"
	"errors"

	"github.com/dedis/cothority/byzcoin"
	"github.com/dedis/cothority/byzcoin/contracts"
	"github.com/dedis/cothority/darc"
	"github.com/dedis/onet/log"
	"github.com/dedis/protobuf"
)

// ContractSpawnerID denotes a contract that can spawn new instances.
var ContractSpawnerID = "spawner"

var SpawnerCoin = byzcoin.NewInstanceID([]byte("SpawnerCoin"))

func contractSpawnerFromBytes(in []byte) (byzcoin.Contract, error) {
	c := &contractSpawner{}
	err := protobuf.Decode(in, &c.SpawnerStruct)
	if err != nil {
		return nil, errors.New("couldn't unmarshal instance data: " + err.Error())
	}
	return c, nil
}

type contractSpawner struct {
	byzcoin.BasicContract
	SpawnerStruct
}

func (c contractSpawner) VerifyInstruction(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, ctxHash []byte) error {
	if inst.GetType() != byzcoin.SpawnType {
		if err := inst.Verify(rst, ctxHash); err != nil {
			return err
		}
	}
	return nil
}

func (c *contractSpawner) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	// Spawn creates a new coin account as a separate instance.
	log.Printf("%+v", inst)
	ca := inst.DeriveID("")
	var instBuf []byte
	cID := inst.Spawn.ContractID
	log.LLvlf3("Spawning %s instance to %x", cID, ca.Slice())
	switch cID {
	case ContractSpawnerID:
		c.ParseArgs(inst.Spawn.Args)
		instBuf, err = protobuf.Encode(&c.SpawnerStruct)
		if err != nil {
			return nil, nil, errors.New("couldn't encode SpawnerInstance: " + err.Error())
		}
	case byzcoin.ContractDarcID:
		if err = c.getCoins(cout, c.CostDarc); err != nil {
			return
		}
		instBuf = inst.Spawn.Args.Search("darc")
		d, err := darc.NewFromProtobuf(instBuf)
		if err != nil {
			return nil, nil, err
		}
		ca = byzcoin.NewInstanceID(d.GetBaseID())
	case contracts.ContractCoinID:
		if err = c.getCoins(cout, c.CostCoin); err != nil {
			return
		}
		coin := &byzcoin.Coin{
			Name: byzcoin.NewInstanceID(inst.Spawn.Args.Search("coinName")),
		}
		for i := range cout {
			if cout[i].Name.Equal(coin.Name) {
				err = coin.SafeAdd(cout[i].Value)
				if err != nil {
					return nil, nil, err
				}
				log.Lvl2("Adding initial balance:", coin.Value)
				err = cout[i].SafeSub(coin.Value)
				if err != nil {
					return nil, nil, err
				}
			}
		}
		darcID = inst.Spawn.Args.Search("darcID")
		h := sha256.New()
		h.Write([]byte("coin"))
		h.Write(darcID)
		ca = byzcoin.NewInstanceID(h.Sum(nil))
		instBuf, err = protobuf.Encode(coin)
		if err != nil {
			return nil, nil, err
		}
	case ContractCredentialID:
		if err = c.getCoins(cout, c.CostCredential); err != nil {
			return
		}
		instBuf = inst.Spawn.Args.Search("credential")
		var cred CredentialStruct
		err = protobuf.Decode(instBuf, &cred)
		if err != nil {
			return nil, nil, err
		}
		darcID = inst.Spawn.Args.Search("darcID")
		h := sha256.New()
		h.Write([]byte("credential"))
		h.Write(darcID)
		ca = byzcoin.NewInstanceID(h.Sum(nil))
	case ContractPopPartyID:
		if err = c.getCoins(cout, c.CostParty); err != nil {
			return
		}
		return contractPopParty{}.Spawn(rst, inst, cout)
	case ContractRoPaSciID:
		if err = c.getCoins(cout, c.CostRoPaSci); err != nil {
			return
		}
		return ContractRoPaSci{}.Spawn(rst, inst, cout)
	default:
		log.Print("Unknown contract", cID)
		return nil, nil, errors.New("don't know how to spawn this type of contract")
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, ca, cID, instBuf, darcID),
	}
	return
}

func (c contractSpawner) getCoins(coins []byzcoin.Coin, cost byzcoin.Coin) error {
	if cost.Value == 0 {
		return nil
	}
	for i := range coins {
		if coins[i].Name.Equal(cost.Name) {
			if coins[i].Value >= cost.Value {
				coins[i].SafeSub(cost.Value)
				return nil
			}
		}
	}
	return errors.New("don't have enough coins for spawning")
}

func (c *contractSpawner) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	switch inst.Invoke.Command {
	case "update":
		// updates the values of the contract
		err = c.SpawnerStruct.ParseArgs(inst.Invoke.Args)
		if err != nil{
			return
		}
	default:
		err = errors.New("personhood contract can only update")
		return
	}

	// Finally update the coin value.
	var ciBuf []byte
	ciBuf, err = protobuf.Encode(&c.SpawnerStruct)
	sc = append(sc, byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID,
		ContractSpawnerID, ciBuf, darcID))
	return
}

func (c *contractSpawner) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	sc = byzcoin.StateChanges{
		byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractSpawnerID, nil, darcID),
	}
	return
}

func (ss *SpawnerStruct) ParseArgs(args byzcoin.Arguments) error {
	for _, cost := range []struct {
		name string
		cost *byzcoin.Coin
	}{
		{"costDarc", &ss.CostDarc},
		{"costCoin", &ss.CostCoin},
		{"costCredential", &ss.CostCredential},
		{"costParty", &ss.CostParty},
		{"costRoPaSci", &ss.CostRoPaSci},
	} {
		if arg := args.Search(cost.name); arg != nil {
			err := protobuf.Decode(arg, cost.cost)
			if err != nil {
				return err
			}
		} else {
			cost.cost = &byzcoin.Coin{contracts.CoinName, 100}
		}
		log.Lvl2("Setting cost of", cost.name, "to", cost.cost.Value)
	}
	return nil
}
