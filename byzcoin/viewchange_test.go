package byzcoin

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3/byzcoin/viewchange"
	"go.dedis.ch/onet/v3/log"
)

// TestService_ViewChange is an end-to-end test for view-change. We kill the
// first nFailures nodes, where the nodes at index 0 is the current leader. The
// node at index nFailures should become the new leader. Then, we try to send a
// transaction to a follower, at index nFailures+1. The new leader (at index
// nFailures) should poll for new transactions and eventually make a new block
// containing that transaction. The new transaction should be stored on all
// followers. Finally, we bring the failed nodes back up and they should
// contain the transactions that they missed.
func TestViewChange_Basic(t *testing.T) {
	testViewChange(t, 4, 1, testInterval)
}

func TestViewChange_Basic2(t *testing.T) {
	if testing.Short() {
		t.Skip("doesn't work on travis correctly due to byzcoinx timeout issue, see #1428")
	}
	testViewChange(t, 7, 2, testInterval)
}

func testViewChange(t *testing.T, nHosts, nFailures int, interval time.Duration) {
	rw := time.Duration(3)
	s := newSerN(t, 1, interval, nHosts, rw)
	defer s.local.CloseAll()

	for _, service := range s.services {
		service.SetPropagationTimeout(2 * interval)
	}

	// Wait for all the genesis config to be written on all nodes.
	genesisInstanceID := InstanceID{}
	for i := range s.services {
		s.waitProofWithIdx(t, genesisInstanceID.Slice(), i)
	}

	// Stop the first nFailures hosts then the node at index nFailures
	// should take over.
	for i := 0; i < nFailures; i++ {
		log.Lvl1("stopping node at index", i)
		s.services[i].TestClose()
		s.hosts[i].Pause()
	}
	// Wait for proof that the new expected leader, s.services[nFailures],
	// has taken over. First, we sleep for the duration that an honest node
	// will wait before starting a view-change. Then, we sleep a little
	// longer for the view-change transaction to be stored in the block.
	for i := 0; i < nFailures; i++ {
		time.Sleep(time.Duration(math.Pow(2, float64(i+1))) * s.interval * rw)
	}
	for doCatchUp := false; !doCatchUp; _, doCatchUp = s.services[nFailures].skService().WaitBlock(s.genesis.SkipChainID(), nil) {
		time.Sleep(interval)
	}
	config, err := s.services[nFailures].LoadConfig(s.genesis.SkipChainID())
	require.NoError(t, err)
	log.Lvl2("Verifying roster", config.Roster.List)
	require.True(t, config.Roster.List[0].Equal(s.services[nFailures].ServerIdentity()))

	// check that the leader is updated for all nodes
	for _, service := range s.services[nFailures:] {
		for doCatchUp := false; !doCatchUp; _, doCatchUp = service.skService().WaitBlock(s.genesis.SkipChainID(), nil) {
			time.Sleep(interval)
		}

		// everyone should have the same leader after the genesis block is stored
		leader, err := service.getLeader(s.genesis.SkipChainID())
		require.NoError(t, err)
		require.NotNil(t, leader)
		require.True(t, leader.Equal(s.services[nFailures].ServerIdentity()))
	}

	// try to send a transaction to the node on index nFailures+1, which is
	// a follower (not the new leader)
	tx1, err := createOneClientTx(s.darc.GetBaseID(), dummyContract, s.value, s.signer)
	require.NoError(t, err)
	s.sendTxTo(t, tx1, nFailures+1)

	// wait for the transaction to be stored on the new leader, because it
	// polls for new transactions
	pr := s.waitProofWithIdx(t, tx1.Instructions[0].InstanceID.Slice(), nFailures)
	require.True(t, pr.InclusionProof.Match(tx1.Instructions[0].InstanceID.Slice()))

	// The transaction should also be stored on followers
	for i := nFailures + 1; i < nHosts; i++ {
		pr = s.waitProofWithIdx(t, tx1.Instructions[0].InstanceID.Slice(), i)
		require.True(t, pr.InclusionProof.Match(tx1.Instructions[0].InstanceID.Slice()))
	}

	// We need to bring the failed (the first nFailures) nodes back up and
	// check that they can synchronise to the latest state.
	for i := 0; i < nFailures; i++ {
		log.Lvl1("starting node at index", i)
		s.hosts[i].Unpause()
		require.NoError(t, s.services[i].startAllChains())
	}
	for i := 0; i < nFailures; i++ {
		pr = s.waitProofWithIdx(t, tx1.Instructions[0].InstanceID.Slice(), i)
		require.True(t, pr.InclusionProof.Match(tx1.Instructions[0].InstanceID.Slice()))
	}
	for doCatchUp := false; !doCatchUp; _, doCatchUp = s.services[nFailures].skService().WaitBlock(s.genesis.SkipChainID(), nil) {
		time.Sleep(s.interval)
	}

	log.Lvl1("Sending 1st tx")
	tx1, err = createOneClientTxWithCounter(s.darc.GetBaseID(), dummyContract, s.value, s.signer, 2)
	require.NoError(t, err)
	s.sendTxToAndWait(t, tx1, nFailures, 10)
	log.Lvl1("Sending 2nd tx")
	tx1, err = createOneClientTxWithCounter(s.darc.GetBaseID(), dummyContract, s.value, s.signer, 3)
	require.NoError(t, err)
	s.sendTxToAndWait(t, tx1, nFailures, 10)
	log.Lvl1("Sent two tx")
}

// Tests that a view change can happen when the leader index is out of bound
func TestViewChange_LeaderIndex(t *testing.T) {
	s := newSerN(t, 1, time.Second, 5, defaultRotationWindow)
	defer s.local.CloseAll()

	err := s.services[0].sendViewChangeReq(viewchange.View{LeaderIndex: -1})
	require.Error(t, err)
	require.Equal(t, "leader index must be positive", err.Error())

	for i := 0; i < 5; i++ {
		err := s.services[i].sendViewChangeReq(viewchange.View{
			ID:          s.genesis.SkipChainID(),
			Gen:         s.genesis.SkipChainID(),
			LeaderIndex: 7,
		})
		require.NoError(t, err)
	}

	time.Sleep(2 * s.interval)

	for _, service := range s.services {
		// everyone should have the same leader after the genesis block is stored
		leader, err := service.getLeader(s.genesis.SkipChainID())
		require.NoError(t, err)
		require.NotNil(t, leader)
		require.True(t, leader.Equal(s.services[2].ServerIdentity()))
	}
}

// Test that old states of a view change that got stuck in the middle of the protocol
// are correctly cleaned if a new block is discovered.
func TestViewChange_LostSync(t *testing.T) {
	s := newSerN(t, 1, time.Second, 5, defaultRotationWindow)
	defer s.local.CloseAll()

	target := s.hosts[1].ServerIdentity

	// Simulate the beginning of a view change
	req := &viewchange.InitReq{
		SignerID: s.services[0].ServerIdentity().ID,
		View: viewchange.View{
			ID:          s.genesis.Hash,
			Gen:         s.genesis.Hash,
			LeaderIndex: 3,
		},
		Signature: []byte{},
	}
	req.Sign(s.services[0].ServerIdentity().GetPrivate())

	err := s.services[0].SendRaw(target, req)
	require.NoError(t, err)

	// worst case scenario where the conode lost connectivity
	// and the view change fails in the other hand so the failing
	// conode is still waiting for requests

	// then new blocks have been added
	tx1, err := createOneClientTxWithCounter(s.darc.GetBaseID(), dummyContract, s.value, s.signer, 1)
	require.Nil(t, err)
	_, err = s.services[1].AddTransaction(&AddTxRequest{
		Version:       CurrentVersion,
		SkipchainID:   s.genesis.SkipChainID(),
		Transaction:   tx1,
		InclusionWait: 5,
	})
	require.Nil(t, err)

	// give enough time for the propagation to be processed
	time.Sleep(1 * time.Second)

	sb, err := s.services[1].db().GetLatestByID(s.genesis.Hash)
	require.NoError(t, err)
	require.NotEqual(t, sb.Hash, s.genesis.Hash)

	// A new view change starts with a block ID different..
	req = &viewchange.InitReq{
		SignerID: s.services[0].ServerIdentity().ID,
		View: viewchange.View{
			ID:          sb.Hash,
			Gen:         s.genesis.SkipChainID(),
			LeaderIndex: 3,
		},
	}
	req.Sign(s.services[0].ServerIdentity().GetPrivate())

	log.OutputToBuf()
	defer log.OutputToOs()

	err = s.services[0].SendRaw(target, req)
	require.NoError(t, err)

	time.Sleep(1 * time.Second) // request handler is asynchronous
	require.NotContains(t, log.GetStdOut(), "a request has been ignored")
	log.OutputToOs()

	// make sure a view change can still happen later
	for i := 0; i < 2; i++ {
		err := s.services[i].sendViewChangeReq(viewchange.View{
			ID:          sb.Hash,
			Gen:         s.genesis.SkipChainID(),
			LeaderIndex: 3,
		})
		require.NoError(t, err)
	}

	time.Sleep(2 * s.interval)

	for _, service := range s.services {
		// everyone should have the same leader after the genesis block is stored
		leader, err := service.getLeader(s.genesis.SkipChainID())
		require.NoError(t, err)
		require.NotNil(t, leader)
		require.True(t, leader.Equal(s.services[3].ServerIdentity()))
	}
}

func TestViewChange_MonitorFailure(t *testing.T) {
	s := newSerN(t, 1, time.Second, 3, defaultRotationWindow)
	defer s.local.CloseAll()

	log.OutputToBuf()
	defer log.OutputToOs()

	// heartbeats an unknown skipchain: this should NOT panic or crash
	s.service().heartbeatsTimeout <- "abc"

	time.Sleep(1 * time.Second)

	stderr := log.GetStdErr()
	require.Contains(t, stderr, "heartbeat monitors are started after the creation")
	require.Contains(t, stderr, "failed to get the latest block")
}
