package personhood

// api for personhood - very minimalistic for the moment, as most of the
// calls are made from javascript.

import (
	"fmt"
	"github.com/dedis/cothority"
	"github.com/dedis/cothority/byzcoin"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/onet"
)

// Client is a structure to communicate with the personhood
// service
type Client struct {
	*onet.Client
}

// NewClient instantiates a new personhood.Client
func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client)TestData(r onet.Roster, bcID skipchain.SkipBlockID, spawnIID byzcoin.InstanceID)(errs []error){
	td := TestStore{
		ByzCoinID: bcID,
		SpawnerIID: spawnIID,
	}
	for _, si := range r.List{
		err := c.SendProtobuf(si, &td, nil)
		if err != nil{
			errs = append(errs, fmt.Errorf("error in node %s: %s", si.Address, err))
		}
	}
	return
}

func (c *Client) WipeParties(r onet.Roster)(errs []error){
	t := true
	pl := PartyList{
		WipeParties: &t,
	}
	for _, si := range r.List{
		err := c.SendProtobuf(si, &pl, nil)
		if err != nil{
			errs = append(errs, fmt.Errorf("error in node %s: %s", si.Address, err))
		}
	}
	return
}

func (c *Client) WipeRoPaScis(r onet.Roster)(errs []error){
	t := true
	pl := RoPaSciList{
		Wipe: &t,
	}
	for _, si := range r.List{
		err := c.SendProtobuf(si, &pl, nil)
		if err != nil{
			errs = append(errs, fmt.Errorf("error in node %s: %s", si.Address, err))
		}
	}
	return
}