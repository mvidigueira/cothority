package personhood

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/dedis/cothority/byzcoin/contracts"

	"github.com/dedis/cothority/byzcoin"
	"github.com/dedis/cothority/darc"
	"github.com/dedis/onet/log"
	"github.com/dedis/protobuf"
)

// ContractRoPaSciID denotes a contract that allows two players to play rock-paper-scissors.
var ContractRoPaSciID = "ropasci"

func ContractRoPaSciFromBytes(in []byte) (byzcoin.Contract, error) {
	c := &ContractRoPaSci{}
	err := protobuf.Decode(in, &c.RoPaSciStruct)
	if err != nil {
		return nil, errors.New("couldn't unmarshal instance data: " + err.Error())
	}
	return c, nil
}

type ContractRoPaSci struct {
	byzcoin.BasicContract
	RoPaSciStruct
}

func (c *ContractRoPaSci) VerifyInstruction(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, ctxHash []byte) error {
	if c.FirstPlayer >= 0{
		return errors.New("this instance has already finished")
	}
	return nil
}

func (c *ContractRoPaSci) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	// Spawn creates a new ropasci as a separate instance.
	ca := inst.DeriveID("")
	log.Lvlf3("Spawning RoPaSci to %x", ca.Slice())
	var rpsBuf []byte
	if rpsBuf = inst.Spawn.Args.Search("struct"); rpsBuf == nil {
		err = errors.New("rock paper scissors needs struct argument")
		return
	}
	err = protobuf.Decode(rpsBuf, &c.RoPaSciStruct)
	if err != nil {
		return nil, nil, errors.New("couldn't decode RoPaScoInstance: " + err.Error())
	}
	if len(c.FirstPlayerHash) != 32 {
		return nil, nil, errors.New("ropasci needs a hash from player 1")
	}
	if len(coins) == 0 || coins[0].Value == 0 {
		return nil, nil, errors.New("ropasci needs some coins as input")
	}
	c.Stake = coins[0]
	cout[0].Value = 0
	rpsBuf, err = protobuf.Encode(c.RoPaSciStruct)
	if err != nil {
		return
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, ca, ContractRoPaSciID, rpsBuf, darcID),
	}
	return
}

func (c *ContractRoPaSci) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	switch inst.Invoke.Command {
	case "second":
		account := inst.Invoke.Args.Search("account")
		if len(account) != 32 {
			return nil, nil, errors.New("need a valid account")
		}
		val, _, cid, _, err := rst.GetValues(account)
		if err != nil{
			return
		}
		if cid != contracts.ContractCoinID{
			return nil, nil, errors.New("account is not of coin type")
		}
		var coin2 byzcoin.Coin
		err = protobuf.Decode(val, &coin2)
		if err != nil{
			return nil, nil, errors.New("couldn't decode coin: " + err.Error())
		}
		if !coin2.Name.Equal(c.Stake.Name){
			return nil, nil, errors.New("not same type of coin")
		}
		if coin2.Value != c.Stake.Value{
			return nil, nil, errors.New("coin-value of player 2 doesn't match player 1")
		}
		choice := inst.Invoke.Args.Search("choice")
		if len(choice) != 1 {
			return nil, nil, errors.New("need a 1-byte choice")
		}
		c.SecondPlayerAccount = byzcoin.NewInstanceID(account)
		c.SecondPlayer = int(choice[0]) % 3

	case "confirm":
		preHash := inst.Invoke.Args.Search("prehash")
		if len(preHash) != 32 {
			return nil, nil, errors.New("prehash needs to be of length 32")
		}
		if bytes.Compare(c.FirstPlayerHash, sha256.Sum256(preHash)[:]) != 0 {
			return nil, nil, errors.New("wrong prehash for first player")
		}
		winnerBuf := inst.Invoke.Args.Search("account")
		if len(winnerBuf) != 32 {
			return nil, nil, errors.New("wrong account for player 1")
		}
		_, _, cid, _, err := rst.GetValues(winnerBuf)
		if err != nil{
			return
		}
		if cid != contracts.ContractCoinID{
			return nil, nil, errors.New("account is not of coin type")
		}
		winner := byzcoin.NewInstanceID(winnerBuf)
		c.FirstPlayer = int(preHash[0]) % 3
		switch (3 + c.FirstPlayer - c.SecondPlayer) % 3{
		case 0:
			log.Lvl2("tie - no winner")
		case 1:
			log.Lvl2("player 1 wins")
		case 2:
			log.Lvl2("player 2 wins")
			winner = c.SecondPlayerAccount
		}
		val, _, _, _, err := rst.GetValues(winnerBuf)
		if err != nil{
			return
		}
		var coin byzcoin.Coin
		err = protobuf.Decode(val, &coin)
		if err != nil{
			return
		}
		coin.Value += c.Stake.Value
		if coin.Value < c.Stake.Value{
			return nil, nil, errors.New("coin overflow")
		}
		coinBuf, err := protobuf.Encode(coin)
		if err != nil{
			return
		}
		sc = append(sc, byzcoin.NewStateChange(byzcoin.Update, winner, contracts.ContractCoinID,
			coinBuf, nil))
	default:
		err = errors.New("rps contract can only 'second' or 'confirm'")
		return
	}

	buf, err := protobuf.Encode(c.RoPaSciStruct)
	if err != nil {
		return
	}
	sc = append(sc, byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID,
		ContractRoPaSciID, buf, darcID))
	return
}

func (c *ContractRoPaSci) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	sc = byzcoin.StateChanges{
		byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractRoPaSciID, nil, darcID),
	}
	return
}

//func CreateRoPaSci(cl *byzcoin.Client, coin, spawner byzcoin.InstanceID,
//	coinSigner, spawnerSigner darc.Signer,
//	d darc.Darc, choice int)(byzcoin.ClientTransaction, error){
//
//}