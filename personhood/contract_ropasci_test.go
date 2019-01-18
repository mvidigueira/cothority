package personhood

import (
	"github.com/dedis/cothority/byzcoin"
	"github.com/dedis/cothority/darc"
	"testing"
)

func TestContractRoPaSci_Invoke(t *testing.T) {
	s := newS(t)
	defer s.Close()
	//
	//ctx, err := combineInstrsAndSign(s.ols, s.signer, byzcoin.Instruction{
	//	InstanceID: byzcoin.NewInstanceID(s.serDarc.GetBaseID()),
	//	Spawn: &byzcoin.Spawn{
	//		ContractID: ContractRoPaSciID,
	//		Args:
	//	}
	//})
}

func combineInstrsAndSign(s *byzcoin.Service, signer darc.Signer, instrs ...byzcoin.Instruction) (ctx byzcoin.ClientTransaction, err error) {
	gscr, err := s.GetSignerCounters(&byzcoin.GetSignerCounters{
		SignerIDs: []string{signer.Identity().String()}})
	if err != nil {
		return
	}
	for i := range instrs {
		gscr.Counters[0]++
		instrs[i].SignerCounter = gscr.Counters
	}
	t := byzcoin.ClientTransaction{
		Instructions: instrs,
	}
	h := t.Instructions.Hash()
	for i := range t.Instructions {
		if err := t.Instructions[i].SignWith(h, signer); err != nil {
			return t, err
		}
	}
	return t, nil
}
