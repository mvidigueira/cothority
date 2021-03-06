package byzcoin

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

func init() {
	// register a service for the test that will do nothing but reply with a chosen response
	onet.RegisterNewServiceWithSuite(testServiceName, pairingSuite, newTestService)
}

func TestClient_NewLedgerCorrupted(t *testing.T) {
	l := onet.NewTCPTest(cothority.Suite)
	servers, roster, _ := l.GenTree(3, true)
	defer l.CloseAll()

	service := servers[0].Service(testServiceName).(*corruptedService)
	signer := darc.NewSignerEd25519(nil, nil)
	msg, err := DefaultGenesisMsg(CurrentVersion, roster, []string{"spawn:dummy"}, signer.Identity())
	require.Nil(t, err)
	c := &Client{
		Client: onet.NewClient(cothority.Suite, testServiceName),
		Roster: *roster,
	}

	sb := skipchain.NewSkipBlock()
	service.CreateGenesisBlockResponse = &CreateGenesisBlockResponse{Skipblock: sb}

	sb.Roster = &onet.Roster{ID: onet.RosterID{}}
	sb.Hash = sb.CalculateHash()
	_, err = newLedgerWithClient(msg, c)
	require.Error(t, err)
	require.Equal(t, "wrong roster in genesis block", err.Error())

	sb.Roster = roster
	sb.Payload = []byte{1, 2, 3}
	sb.Hash = sb.CalculateHash()
	_, err = newLedgerWithClient(msg, c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fail to decode data:")

	sb.Payload = []byte{}
	sb.Hash = sb.CalculateHash()
	_, err = newLedgerWithClient(msg, c)
	require.Error(t, err)
	require.Equal(t, "genesis darc tx should only have one instruction", err.Error())

	data := &DataBody{
		TxResults: []TxResult{
			TxResult{ClientTransaction: ClientTransaction{Instructions: []Instruction{Instruction{}}}},
		},
	}
	sb.Payload, err = protobuf.Encode(data)
	sb.Hash = sb.CalculateHash()
	require.NoError(t, err)
	_, err = newLedgerWithClient(msg, c)
	require.Error(t, err)
	require.Equal(t, "didn't get a spawn instruction", err.Error())

	data.TxResults[0].ClientTransaction.Instructions[0].Spawn = &Spawn{
		Args: []Argument{
			Argument{
				Name:  "darc",
				Value: []byte{1, 2, 3},
			},
		},
	}
	sb.Payload, err = protobuf.Encode(data)
	sb.Hash = sb.CalculateHash()
	require.NoError(t, err)
	_, err = newLedgerWithClient(msg, c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fail to decode the darc:")

	darcBytes, _ := protobuf.Encode(&darc.Darc{})
	data.TxResults[0].ClientTransaction.Instructions[0].Spawn = &Spawn{
		Args: []Argument{
			Argument{
				Name:  "darc",
				Value: darcBytes,
			},
		},
	}
	sb.Payload, err = protobuf.Encode(data)
	sb.Hash = sb.CalculateHash()
	require.NoError(t, err)
	_, err = newLedgerWithClient(msg, c)
	require.Error(t, err)
	require.Equal(t, "wrong darc spawned", err.Error())
}

func TestClient_GetProof(t *testing.T) {
	l := onet.NewTCPTest(cothority.Suite)
	servers, roster, _ := l.GenTree(3, true)
	registerDummy(servers)
	defer l.CloseAll()

	// Initialise the genesis message and send it to the service.
	signer := darc.NewSignerEd25519(nil, nil)
	msg, err := DefaultGenesisMsg(CurrentVersion, roster, []string{"spawn:dummy"}, signer.Identity())
	msg.BlockInterval = 100 * time.Millisecond
	require.Nil(t, err)

	// The darc inside it should be valid.
	d := msg.GenesisDarc
	require.Nil(t, d.Verify(true))

	c, csr, err := NewLedger(msg, false)
	require.Nil(t, err)

	// Create a new transaction.
	value := []byte{5, 6, 7, 8}
	kind := "dummy"
	tx, err := createOneClientTx(d.GetBaseID(), kind, value, signer)
	require.Nil(t, err)
	_, err = c.AddTransaction(tx)
	require.Nil(t, err)

	// We should have a proof of our transaction in the skipchain.
	newID := tx.Instructions[0].Hash()
	var p *GetProofResponse
	var i int
	for i = 0; i < 10; i++ {
		time.Sleep(4 * msg.BlockInterval)
		var err error
		p, err = c.GetProof(newID)
		if err != nil {
			continue
		}
		if p.Proof.InclusionProof.Match(newID) {
			break
		}
	}
	require.NotEqual(t, 10, i, "didn't get proof in time")
	require.Nil(t, p.Proof.Verify(csr.Skipblock.SkipChainID()))
	k, v0, _, _, err := p.Proof.KeyValue()
	require.Nil(t, err)
	require.Equal(t, k, newID)
	require.Equal(t, value, v0)
}

func TestClient_GetProofCorrupted(t *testing.T) {
	l := onet.NewTCPTest(cothority.Suite)
	servers, roster, _ := l.GenTree(3, true)
	defer l.CloseAll()

	service := servers[0].Service(testServiceName).(*corruptedService)

	c := &Client{
		Client: onet.NewClient(cothority.Suite, testServiceName),
		Roster: *roster,
	}

	sb := skipchain.NewSkipBlock()
	sb.Data = []byte{1, 2, 3}
	service.GetProofResponse = &GetProofResponse{
		Proof: Proof{Latest: *sb},
	}

	_, err := c.GetProof([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Error while decoding field")
}

// Create a streaming client and add blocks in the background. The client
// should receive valid blocks.
func TestClient_Streaming(t *testing.T) {
	l := onet.NewTCPTest(cothority.Suite)
	servers, roster, _ := l.GenTree(3, true)
	registerDummy(servers)
	defer l.CloseAll()

	// Initialise the genesis message and send it to the service.
	signer := darc.NewSignerEd25519(nil, nil)
	msg, err := DefaultGenesisMsg(CurrentVersion, roster, []string{"spawn:dummy"}, signer.Identity())
	msg.BlockInterval = time.Second
	require.Nil(t, err)

	// The darc inside it should be valid.
	d := msg.GenesisDarc
	require.Nil(t, d.Verify(true))

	c, csr, err := NewLedger(msg, false)
	require.Nil(t, err)

	n := 2
	go func() {
		time.Sleep(100 * time.Millisecond)
		for i := 0; i < n; i++ {
			value := []byte{5, 6, 7, 8}
			kind := "dummy"
			tx, err := createOneClientTxWithCounter(d.GetBaseID(), kind, value, signer, uint64(i)+1)
			// Need log.ErrFatal here, else it races with the rest of the code that
			// uses 't'.
			log.ErrFatal(err)
			_, err = c.AddTransaction(tx)
			log.ErrFatal(err)

			// sleep for a block interval so we create multiple blocks
			time.Sleep(msg.BlockInterval)
		}
	}()

	// Start collecting transactions
	c1 := NewClientKeep(csr.Skipblock.Hash, *roster)
	var xMut sync.Mutex
	var x int
	done := make(chan bool)
	cb := func(resp StreamingResponse, err error) {
		xMut.Lock()
		defer xMut.Unlock()
		if err != nil {
			// If we already closed the done channel, then it must
			// be after we've seen n blocks.
			require.True(t, x >= n)
			return
		}

		var body DataBody
		require.NotNil(t, resp.Block)
		err = protobuf.DecodeWithConstructors(resp.Block.Payload, &body, network.DefaultConstructors(cothority.Suite))
		require.NoError(t, err)
		for _, tx := range body.TxResults {
			for _, instr := range tx.ClientTransaction.Instructions {
				require.Equal(t, instr.Spawn.ContractID, "dummy")
			}
		}
		if x == n-1 {
			// We got n blocks, so we close the done channel.
			close(done)
		}
		x++
	}

	go func() {
		err = c1.StreamTransactions(cb)
		require.Nil(t, err)
	}()
	select {
	case <-done:
	case <-time.After(time.Duration(n)*msg.BlockInterval + time.Second):
		require.Fail(t, "should have got n transactions")
	}
	require.NoError(t, c1.Close())

	// client.Close() won't close the service if there are no more
	// transactions, so send some more to make sure the service gets an
	// error and stops its streaming go-routing.
	for i := 0; i < 2; i++ {
		value := []byte{5, 6, 7, 8}
		kind := "dummy"
		// We added two transactions before, so the latest counter is 2
		// so we must start the counter here at 3.
		tx, err := createOneClientTxWithCounter(d.GetBaseID(), kind, value, signer, uint64(i)+3)
		require.Nil(t, err)
		_, err = c.AddTransactionAndWait(tx, 4)
		require.Nil(t, err)
	}
}

const testServiceName = "TestByzCoin"

type corruptedService struct {
	*Service

	// corrupted replies
	GetProofResponse           *GetProofResponse
	CreateGenesisBlockResponse *CreateGenesisBlockResponse
}

func newTestService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor:       onet.NewServiceProcessor(c),
		contracts:              make(map[string]ContractFn),
		txBuffer:               newTxBuffer(),
		storage:                &bcStorage{},
		darcToSc:               make(map[string]skipchain.SkipBlockID),
		stateChangeCache:       newStateChangeCache(),
		stateChangeStorage:     newStateChangeStorage(c),
		heartbeatsTimeout:      make(chan string, 1),
		closeLeaderMonitorChan: make(chan bool, 1),
		heartbeats:             newHeartbeats(),
		viewChangeMan:          newViewChangeManager(),
		streamingMan:           streamingManager{},
		closed:                 true,
	}

	cs := &corruptedService{Service: s}
	err := s.RegisterHandlers(cs.GetProof, cs.CreateGenesisBlock)

	return cs, err
}

func (cs *corruptedService) GetProof(req *GetProof) (resp *GetProofResponse, err error) {
	return cs.GetProofResponse, nil
}

func (cs *corruptedService) CreateGenesisBlock(req *CreateGenesisBlock) (*CreateGenesisBlockResponse, error) {
	return cs.CreateGenesisBlockResponse, nil
}
