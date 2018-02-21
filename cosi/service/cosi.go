package service

import (
	"errors"
	"time"

	"github.com/dedis/cothority"
	"github.com/dedis/cothority/cosi/protocol"
	"github.com/dedis/kyber/sign/cosi"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// This file contains all the code to run a CoSi service. It is used to reply to
// client request for signing something using CoSi.
// As a prototype, it just signs and returns. It would be very easy to write an
// updated version that chains all signatures for example.

// ServiceName is the name to refer to the CoSi service
const ServiceName = "CoSiService"

func init() {
	onet.RegisterNewService(ServiceName, newCoSiService)
	network.RegisterMessage(&SignatureRequest{})
	network.RegisterMessage(&SignatureResponse{})
}

// Service is the service that handles collective signing operations
type Service struct {
	*onet.ServiceProcessor
	suite cosi.Suite
}

// SignatureRequest is what the Cosi service is expected to receive from clients.
type SignatureRequest struct {
	Message []byte
	Roster  *onet.Roster
}

// SignatureResponse is what the Cosi service will reply to clients.
type SignatureResponse struct {
	Hash      []byte
	Signature []byte
}

// SignatureRequest treats external request to this service.
func (s *Service) SignatureRequest(req *SignatureRequest) (network.Message, error) {
	// generate the tree
	nNodes := len(req.Roster.List)
	tree := req.Roster.GenerateNaryTreeWithRoot(nNodes, s.ServerIdentity())
	if tree == nil {
		return nil, errors.New("failed to generate tree")
	}
	pi, err := s.CreateProtocol(protocol.DefaultProtocolName, tree)
	if err != nil {
		return nil, errors.New("Couldn't make new protocol: " + err.Error())
	}

	// configure the protocol
	p := pi.(*protocol.CoSiRootNode)
	p.CreateProtocol = s.CreateProtocol
	p.Msg = req.Message
	// TODO is there an optimal way to find out the number of subtrees?
	p.NSubtrees = nNodes / 10
	p.Timeout = time.Second * 5
	if p.NSubtrees < 1 {
		p.NSubtrees = 1
	}

	// start the protocol
	log.Lvl3("Cosi Service starting up root protocol")
	if err = pi.Start(); err != nil {
		return nil, err
	}

	if log.DebugVisible() > 1 {
		log.Printf("%s: Signed a message.\n", time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	}

	// wait for reply
	var sig []byte
	select {
	case sig = <-p.FinalSignature:
	case <-time.After(p.Timeout + time.Second):
		return nil, errors.New("protocol timed out")
	}

	// the hash is the message cosi actually signs, ideally cosi protocol
	// should tell us what it is, here we recompute it and then return
	h := s.suite.Hash()
	h.Write(req.Message)
	return &SignatureResponse{h.Sum(nil), sig}, nil
}

// NewProtocol is called on all nodes of a Tree (except the root, since it is
// the one starting the protocol) so it's the Service that will be called to
// generate the PI on all others node.
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("Cosi Service received New Protocol event")
	if tn.ProtocolName() == protocol.DefaultProtocolName {
		return protocol.NewDefaultProtocol(tn)
	}
	if tn.ProtocolName() == protocol.DefaultSubProtocolName {
		return protocol.NewDefaultSubProtocol(tn)
	}
	return nil, errors.New("no such protocol " + tn.ProtocolName())
}

func newCoSiService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		suite:            cothority.Suite,
	}
	if err := s.RegisterHandler(s.SignatureRequest); err != nil {
		log.Error("couldn't register message:", err)
		return nil, err
	}
	if _, err := c.ProtocolRegister(protocol.DefaultProtocolName, protocol.NewDefaultProtocol); err != nil {
		log.Error("couldn't register main protocol:", err)
		return nil, err
	}
	if _, err := c.ProtocolRegister(protocol.DefaultSubProtocolName, protocol.NewDefaultSubProtocol); err != nil {
		log.Error("couldn't register sub protocol:", err)
		return nil, err
	}
	return s, nil
}
