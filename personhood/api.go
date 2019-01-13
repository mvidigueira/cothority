package personhood

// api for personhood - very minimalistic for the moment, as most of the
// calls are made from javascript.

import (
	"github.com/dedis/cothority"
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
