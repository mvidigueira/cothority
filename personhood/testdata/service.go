package testdata

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// Used for tests
var templateID onet.ServiceID

// ServiceName of the personhood service
var ServiceName = "TestData"

func init() {
	var err error
	templateID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
}

// Service is our template-service
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	storage *storage1
}

// TestStore allows easier testing of the mobile apps by giving an endpoint
// where current testing data can be stored.
func (s *Service) TestStore(ts *TestStore) (*TestStore, error) {
	if ts.ByzCoinID != nil && len(ts.ByzCoinID) == 32 {
		log.Lvlf1("Storing TestStore %x / %x", ts.ByzCoinID, ts.SpawnerIID.Slice())
		s.storage.Ts.ByzCoinID = ts.ByzCoinID
		s.storage.Ts.SpawnerIID = ts.SpawnerIID
	} else {
		log.Lvlf1("Retrieving TestStore %x / %x", s.storage.Ts.ByzCoinID[:], s.storage.Ts.SpawnerIID[:])
	}
	return &s.storage.Ts, s.save()
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if err := s.RegisterHandlers(s.TestStore); err != nil {
		return nil, errors.New("couldn't register messages")
	}

	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	return s, nil
}
