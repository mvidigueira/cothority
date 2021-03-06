package contracts

import (
	"encoding/binary"
	"testing"
	"time"

	"go.dedis.ch/onet/v3/network"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/protobuf"

	"go.dedis.ch/cothority/v3/darc"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
)

// Note: Those tests relie on the Value contract, hence it is not possible to
//       include this file in the byzcoin package.

func TestDeferred_ScenarioSingleInstruction(t *testing.T) {
	// Since every method relies on the execution of a previous ones, I am not
	// unit test but rather creating a scenario:
	//
	// 1. Spawn a new contract
	// 2. Invoke two "addProff"
	// 3. Invoke an "execRoot"

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------
	rootInstructionValue := []byte("aef123456789fab")

	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue,
						},
					},
				},
			},
		},
	}

	expireBlockIndexInt := uint64(6000)
	expireBlockIndexBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(expireBlockIndexBuf, expireBlockIndexInt)
	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
					{
						Name:  "expireBlockIndex",
						Value: expireBlockIndexBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	rootHash := result.InstructionHashes

	// ------------------------------------------------------------------------
	// 2.1 Invoke a first "addProof"
	// ------------------------------------------------------------------------

	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err := signer.Sign(rootHash[0]) // == index
	require.Nil(t, err)
	// signature[1] = 0xf

	index := uint32(0)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	proposedTransaction.Instructions[0].SignerIdentities = append(proposedTransaction.Instructions[0].SignerIdentities, identity)
	proposedTransaction.Instructions[0].Signatures = append(proposedTransaction.Instructions[0].Signatures, signature)
	result.ProposedTransaction = proposedTransaction
	resultBuf, err := protobuf.Encode(&result)
	require.Nil(t, err)

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, resultBuf)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].SignerIdentities), 1)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[0].SignerIdentities[0]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].Signatures), 1)
	require.Equal(t, result.ProposedTransaction.Instructions[0].Signatures[0], signature)
	// Default NumExecution should be 1
	require.Equal(t, result.NumExecution, uint64(1))

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 2.2 Invoke a second "addProof"
	// ------------------------------------------------------------------------
	//
	// Lets try to add another signer. Here I am still using the previous signer
	// to send the transaction because he has the right to. I am just trying to
	// see if adding another new identity and signature will result in having
	// two identities and two signatures.
	//

	signer2 := darc.NewSignerEd25519(nil, nil)
	identity = signer2.Identity()
	identityBuf, err = protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err = signer2.Sign(rootHash[0]) // == index
	require.Nil(t, err)
	// signature[1] = 0xf // Simulates a wrong signature

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{3},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	proposedTransaction.Instructions[0].SignerIdentities = append(proposedTransaction.Instructions[0].SignerIdentities, identity)
	proposedTransaction.Instructions[0].Signatures = append(proposedTransaction.Instructions[0].Signatures, signature)
	result.ProposedTransaction = proposedTransaction
	resultBuf, err = protobuf.Encode(&result)
	require.Nil(t, err)

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, resultBuf)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].SignerIdentities), 2)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[0].SignerIdentities[1]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].Signatures), 2)
	require.Equal(t, result.ProposedTransaction.Instructions[0].Signatures[1], signature)

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 3. Invoke an "execRoot" command
	// ------------------------------------------------------------------------

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "execProposedTx",
			},
			SignerCounter: []uint64{4},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	// Need to sleep because we can't predict the output (hence the 'nil')
	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))
	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	protobuf.Decode(dataBuf, &result)
	require.Equal(t, 1, len(result.ExecResult))

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(result.ExecResult[0]), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(result.ExecResult[0]))

	valueRes, _, _, err := pr.Get(result.ExecResult[0])
	require.Nil(t, err)

	// Such a miracle to retrieve this value that was set at the begining
	require.Equal(t, valueRes, rootInstructionValue)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 4. Invoke an "execRoot" command a second time. Since NumExecution should
	//    be at 0, we expect it to fail.
	//    NOTE: We are trying to spawn two times a contract with the sane id,
	//          which is not likely to create two instances. Here we are only
	//          testing if the check of the NumExecution works.
	// ------------------------------------------------------------------------

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "execProposedTx",
			},
			SignerCounter: []uint64{5},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID = ctx.Instructions[0].DeriveID("")

	// Need to sleep because we can't predict the output (hence the 'nil')
	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Error(t, err)

	local.WaitDone(genesisMsg.BlockInterval)
}

func TestDeferred_ScenarioMultiInstructions(t *testing.T) {
	// Since every method relies on the execution of a previous ones, I am not
	// unit test but rather creating a scenario:
	//
	// 1. Spawn a new contract with two instruction
	// 2. Invoke two "addProff"
	// 3. Invoke an "execRoot"

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------
	rootInstructionValue1 := []byte("aef123456789fab")
	rootInstructionValue2 := []byte("1234aef")

	// We spawn two value contracts
	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue1,
						},
					},
				},
			},
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue2,
						},
					},
				},
			},
		},
	}

	expireBlockIndexInt := uint64(6000)
	expireBlockIndexBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(expireBlockIndexBuf, expireBlockIndexInt)
	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
					{
						Name:  "expireBlockIndex",
						Value: expireBlockIndexBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	rootHash := result.InstructionHashes

	// ------------------------------------------------------------------------
	// 2.1 Invoke a first "addProof" on the first instruction
	// ------------------------------------------------------------------------

	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err := signer.Sign(rootHash[0]) // == index
	require.Nil(t, err)
	// signature[1] = 0xf

	index := uint32(0)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	proposedTransaction.Instructions[0].SignerIdentities = append(proposedTransaction.Instructions[0].SignerIdentities, identity)
	proposedTransaction.Instructions[0].Signatures = append(proposedTransaction.Instructions[0].Signatures, signature)
	result.ProposedTransaction = proposedTransaction
	resultBuf, err := protobuf.Encode(&result)
	require.Nil(t, err)

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, resultBuf)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].SignerIdentities), 1)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[0].SignerIdentities[0]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].Signatures), 1)
	require.Equal(t, result.ProposedTransaction.Instructions[0].Signatures[0], signature)
	// Default NumExecution should be 1
	require.Equal(t, result.NumExecution, uint64(1))

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 2.2 Invoke a second "addProof" on the second instruction
	// ------------------------------------------------------------------------

	signature, err = signer.Sign(rootHash[1]) // == index
	require.Nil(t, err)

	index = uint32(1)
	indexBuf = make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{3},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[1].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[1].SignerIdentities), 1)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[1].SignerIdentities[0]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[1].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[1].Signatures), 1)
	require.Equal(t, result.ProposedTransaction.Instructions[1].Signatures[0], signature)

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 3. Invoke an "execRoot" command
	// ------------------------------------------------------------------------

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "execProposedTx",
			},
			SignerCounter: []uint64{4},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	// Need to sleep because we can't predict the output (hence the 'nil')
	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))
	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	protobuf.Decode(dataBuf, &result)

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(result.ExecResult[0]), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(result.ExecResult[0]))

	valueRes, _, _, err := pr.Get(result.ExecResult[0])
	require.Nil(t, err)

	// Such a miracle to retrieve this value that was set at the begining
	require.Equal(t, valueRes, rootInstructionValue1)

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(result.ExecResult[1]), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(result.ExecResult[1]))

	valueRes, _, _, err = pr.Get(result.ExecResult[1])
	require.Nil(t, err)

	// Such a miracle to retrieve this value that was set at the begining
	require.Equal(t, valueRes, rootInstructionValue2)

	local.WaitDone(genesisMsg.BlockInterval)
}

func TestDeferred_ScenarioMultiInstructionsDifferentSigners(t *testing.T) {
	// I commit two instructions that are siged by two different signers. The
	// second signer has no right to sign the instruction, so we expect the transaction to fail.

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------
	rootInstructionValue1 := []byte("aef123456789fab")
	rootInstructionValue2 := []byte("1234aef")

	// We spawn two value contracts
	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue1,
						},
					},
				},
			},
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue2,
						},
					},
				},
			},
		},
	}

	expireBlockIndexInt := uint64(6000)
	expireBlockIndexBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(expireBlockIndexBuf, expireBlockIndexInt)
	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
					{
						Name:  "expireBlockIndex",
						Value: expireBlockIndexBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	rootHash := result.InstructionHashes

	// ------------------------------------------------------------------------
	// 2.1 Invoke a first "addProof" on the first instruction
	// ------------------------------------------------------------------------

	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err := signer.Sign(rootHash[0]) // == index
	require.Nil(t, err)
	// signature[1] = 0xf

	index := uint32(0)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	proposedTransaction.Instructions[0].SignerIdentities = append(proposedTransaction.Instructions[0].SignerIdentities, identity)
	proposedTransaction.Instructions[0].Signatures = append(proposedTransaction.Instructions[0].Signatures, signature)
	result.ProposedTransaction = proposedTransaction
	resultBuf, err := protobuf.Encode(&result)
	require.Nil(t, err)

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, resultBuf)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].SignerIdentities), 1)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[0].SignerIdentities[0]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].Signatures), 1)
	require.Equal(t, result.ProposedTransaction.Instructions[0].Signatures[0], signature)
	// Default NumExecution should be 1
	require.Equal(t, result.NumExecution, uint64(1))

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 2.2 Invoke a second "addProof" on the second instruction, but with a
	//     different signer
	// ------------------------------------------------------------------------

	signer2 := darc.NewSignerEd25519(nil, nil)

	identity = signer2.Identity()
	identityBuf, err = protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err = signer2.Sign(rootHash[1]) // == index
	require.Nil(t, err)

	index = uint32(1)
	indexBuf = make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{3},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[1].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[1].SignerIdentities), 1)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[1].SignerIdentities[0]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[1].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[1].Signatures), 1)
	require.Equal(t, result.ProposedTransaction.Instructions[1].Signatures[0], signature)

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 3. Invoke an "execRoot" command. This one will fail since one of the
	//    instruction is signed by an unauthorized signer.
	// ------------------------------------------------------------------------

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "execProposedTx",
			},
			SignerCounter: []uint64{4},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	myID = ctx.Instructions[0].DeriveID("")

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	// Need to sleep because we can't predict the output (hence the 'nil')
	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Error(t, err)

	local.WaitDone(genesisMsg.BlockInterval)
}

func TestDeferred_WrongSignature(t *testing.T) {
	// If a client performs an "addProof" with a wrong signature, then it should
	// produce an error and reject the transaction

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------
	rootInstructionValue := []byte("aef123456789fab")

	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue,
						},
					},
				},
			},
		},
	}

	expireBlockIndexInt := uint64(6000)
	expireBlockIndexBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(expireBlockIndexBuf, expireBlockIndexInt)
	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
					{
						Name:  "expireBlockIndex",
						Value: expireBlockIndexBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	rootHash := result.InstructionHashes

	// ------------------------------------------------------------------------
	// 2 Invoke an "addProof" with a wrong signature
	// ------------------------------------------------------------------------

	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err := signer.Sign(rootHash[0]) // == index
	require.Nil(t, err)
	signature[1] = 0xf

	index := uint32(0)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)
	myID = ctx.Instructions[0].DeriveID("")

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Error(t, err)

	local.WaitDone(genesisMsg.BlockInterval)
}

func TestDeferred_DuplicateIdentity(t *testing.T) {
	// We do not store duplicates of identities. If someone tries to add an
	// identity that is already added, it returns an error.

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------
	rootInstructionValue := []byte("aef123456789fab")

	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue,
						},
					},
				},
			},
		},
	}

	expireBlockIndexInt := uint64(6000)
	expireBlockIndexBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(expireBlockIndexBuf, expireBlockIndexInt)
	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
					{
						Name:  "expireBlockIndex",
						Value: expireBlockIndexBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	rootHash := result.InstructionHashes

	// ------------------------------------------------------------------------
	// 2 Invoke an "addProof"
	// ------------------------------------------------------------------------

	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err := signer.Sign(rootHash[0]) // == index
	require.Nil(t, err)

	index := uint32(0)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 3 Invoke a second time the same "addProof"
	// ------------------------------------------------------------------------

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{3},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(ctx.Instructions[0].DeriveID("").Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Error(t, err)

	local.WaitDone(genesisMsg.BlockInterval)
}

func TestDeferred_ExpireBlockIndex(t *testing.T) {
	// We set an "expireBlockIndex" to 0, which should prevent any invoke.

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------
	rootInstructionValue := []byte("aef123456789fab")

	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue,
						},
					},
				},
			},
		},
	}

	expireBlockIndexInt := uint64(6000)
	expireBlockIndexBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(expireBlockIndexBuf, expireBlockIndexInt)
	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
					{
						Name:  "expireBlockIndex",
						Value: expireBlockIndexBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	rootHash := result.InstructionHashes

	// ------------------------------------------------------------------------
	// 2 Invoke an "addProof"
	// ------------------------------------------------------------------------

	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err := signer.Sign(rootHash[0]) // == index
	require.Nil(t, err)

	index := uint32(0)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(ctx.Instructions[0].DeriveID("").Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Error(t, err)

	local.WaitDone(genesisMsg.BlockInterval)
}

func TestDeferred_ExecWithNoProof(t *testing.T) {
	// We will sign the proposed transaction with no proof on it. We expect it
	// to fail

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------
	rootInstructionValue := []byte("aef123456789fab")

	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue,
						},
					},
				},
			},
		},
	}

	expireBlockIndexInt := uint64(6000)
	expireBlockIndexBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(expireBlockIndexBuf, expireBlockIndexInt)
	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
					{
						Name:  "expireBlockIndex",
						Value: expireBlockIndexBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 2. Invoke an "execProposedTx" command
	// ------------------------------------------------------------------------

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "execProposedTx",
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	// Need to sleep because we can't predict the output (hence the 'nil')
	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))
	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	local.WaitDone(genesisMsg.BlockInterval)

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(dataBuf), 2*genesisMsg.BlockInterval, nil)
	require.Error(t, err)

	local.WaitDone(genesisMsg.BlockInterval)
}

func TestDeferred_InstructionsDependent(t *testing.T) {
	// Here we run a deferred transaction and check if instructions can be
	// sequentially dependent. We simply test this by invoking a first
	// delete instruction on a value contract, then we try to read the deleted
	// contract. If we can't, we know instructions are sequentially dependent.
	//
	// 0.1.  Setup
	// 0.2.  Spawn a value contract
	// 1.    Spawn the deferred contract with two instructions
	// 2.    Invoke a first "addProof" to sign the proposed transaction
	// 3.    Invoke a second "addProof" to sign the proposed transaction
	// 4.    Invoke an "execProposedTx"

	// ------------------------------------------------------------------------
	// 0.1. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "delete:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx", "invoke:value.update"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 0.2. Spawn a value contract
	// ------------------------------------------------------------------------

	myvalue := []byte("1234")
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractValueID,
				Args: []byzcoin.Argument{{
					Name:  "value",
					Value: myvalue,
				}},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	valueID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(valueID.Slice()), 2*genesisMsg.BlockInterval, myvalue)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(valueID.Slice()))

	v0, _, _, err := pr.Get(valueID.Slice())
	require.Nil(t, err)
	require.Equal(t, myvalue, v0)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 1. Spawn our deferred contract. We provide the previous ID.
	// ------------------------------------------------------------------------
	rootInstructionValue := []byte("aef123456789fab")

	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: valueID,
				Delete: &byzcoin.Delete{
					ContractID: "value",
				},
			},
			byzcoin.Instruction{
				InstanceID: valueID,
				Invoke: &byzcoin.Invoke{
					ContractID: "value",
					Command:    "update",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue,
						},
					},
				},
			},
		},
	}

	expireBlockIndexInt := uint64(6000)
	expireBlockIndexBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(expireBlockIndexBuf, expireBlockIndexInt)
	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
					{
						Name:  "expireBlockIndex",
						Value: expireBlockIndexBuf,
					},
				},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	rootHash := result.InstructionHashes

	// ------------------------------------------------------------------------
	// 2. Invoke a first "addProof"
	// ------------------------------------------------------------------------

	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err := signer.Sign(rootHash[0]) // == index
	require.Nil(t, err)

	index := uint32(0)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{3},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	proposedTransaction.Instructions[0].SignerIdentities = append(proposedTransaction.Instructions[0].SignerIdentities, identity)
	proposedTransaction.Instructions[0].Signatures = append(proposedTransaction.Instructions[0].Signatures, signature)
	result.ProposedTransaction = proposedTransaction
	resultBuf, err := protobuf.Encode(&result)
	require.Nil(t, err)

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, resultBuf)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].SignerIdentities), 1)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[0].SignerIdentities[0]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].Signatures), 1)
	require.Equal(t, result.ProposedTransaction.Instructions[0].Signatures[0], signature)
	// Default NumExecution should be 1
	require.Equal(t, result.NumExecution, uint64(1))

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 3. Invoke a second "addProof" (second instruction)
	// ------------------------------------------------------------------------

	signature, err = signer.Sign(rootHash[1]) // == index
	require.Nil(t, err)

	index = uint32(1)
	indexBuf = make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{4},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	proposedTransaction.Instructions[1].SignerIdentities = append(proposedTransaction.Instructions[1].SignerIdentities, identity)
	proposedTransaction.Instructions[1].Signatures = append(proposedTransaction.Instructions[1].Signatures, signature)
	result.ProposedTransaction = proposedTransaction
	resultBuf, err = protobuf.Encode(&result)
	require.Nil(t, err)

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, resultBuf)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 2)
	require.Equal(t, result.ExpireBlockIndex, expireBlockIndexInt)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[1].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[1].SignerIdentities), 1)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[1].SignerIdentities[0]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[1].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[1].Signatures), 1)
	require.Equal(t, result.ProposedTransaction.Instructions[1].Signatures[0], signature)
	// Default NumExecution should be 1
	require.Equal(t, result.NumExecution, uint64(1))

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 4. Invoke an "execRoot" command
	// ------------------------------------------------------------------------

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "execProposedTx",
			},
			SignerCounter: []uint64{5},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	// Need to sleep because we can't predict the output (hence the 'nil')
	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(ctx.Instructions[0].DeriveID("").Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Error(t, err)

	local.WaitDone(genesisMsg.BlockInterval)

}

func TestDeferred_DefaultExpireBlockIdx(t *testing.T) {
	// Here we invoke a deferred contract without giving an expire block index.
	// We expect then the block index to be the default value we use, which is
	// `current_blockIdx + 50`. In this case, current_blockIdx equals 0.

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	expectedBlockIdx := uint64(50)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------
	rootInstructionValue := []byte("aef123456789fab")

	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: "value",
					Args: byzcoin.Arguments{
						byzcoin.Argument{
							Name:  "value",
							Value: rootInstructionValue,
						},
					},
				},
			},
		},
	}

	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Equal(t, result.ExpireBlockIndex, expectedBlockIdx)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)
}

func TestDeferred_ScenarioUpdateConfig(t *testing.T) {
	// In this test we use Invoke:config.update_config as the proposed
	// transaction. We update the config and check if the changes are applied.
	//
	// 1. Spawn a new contract with config as the deferred transaction
	// 2. Invoke an "addProff"
	// 3. Invoke an "execRoot"

	// ------------------------------------------------------------------------
	// 0. Set up
	// ------------------------------------------------------------------------
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:value", "spawn:deferred", "invoke:deferred.addProof",
			"invoke:deferred.execProposedTx"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	// ------------------------------------------------------------------------
	// 1. Spawn
	// ------------------------------------------------------------------------

	// Get the latest chain config
	prr, err := cl.GetProof(byzcoin.ConfigInstanceID.Slice())
	require.Nil(t, err)
	proof := prr.Proof

	_, value, _, _, err := proof.KeyValue()
	require.Nil(t, err)
	config := byzcoin.ChainConfig{}
	err = protobuf.DecodeWithConstructors(value, &config, network.DefaultConstructors(cothority.Suite))
	require.Nil(t, err)
	config.BlockInterval, err = time.ParseDuration("7s")
	require.Nil(t, err)
	config.MaxBlockSize += 10

	configBuf, err := protobuf.Encode(&config)
	require.Nil(t, err)

	invoke := byzcoin.Invoke{
		ContractID: byzcoin.ContractConfigID,
		Command:    "update_config",
		Args: []byzcoin.Argument{
			{
				Name:  "config",
				Value: configBuf,
			},
		},
	}

	proposedTransaction := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			byzcoin.Instruction{
				InstanceID: byzcoin.ConfigInstanceID,
				Invoke:     &invoke,
			},
		},
	}

	proposedTransactionBuf, err := protobuf.Encode(&proposedTransaction)
	require.Nil(t, err)

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDeferredID,
				Args: []byzcoin.Argument{
					{
						Name:  "proposedTransaction",
						Value: proposedTransactionBuf,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	myID := ctx.Instructions[0].DeriveID("")
	pr, err := cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err := pr.Get(myID.Slice())
	require.Nil(t, err)
	result := byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.Empty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Empty(t, result.ProposedTransaction.Instructions[0].Signatures)

	local.WaitDone(genesisMsg.BlockInterval)

	rootHash := result.InstructionHashes

	// ------------------------------------------------------------------------
	// 2.1 Invoke a first "addProof"
	// ------------------------------------------------------------------------

	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	require.Nil(t, err)

	signature, err := signer.Sign(rootHash[0]) // == index
	require.Nil(t, err)
	// signature[1] = 0xf

	index := uint32(0)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "addProof",
				Args: []byzcoin.Argument{
					{
						Name:  "identity",
						Value: identityBuf,
					},
					{
						Name:  "signature",
						Value: signature,
					},
					{
						Name:  "index",
						Value: indexBuf,
					},
				},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	proposedTransaction.Instructions[0].SignerIdentities = append(proposedTransaction.Instructions[0].SignerIdentities, identity)
	proposedTransaction.Instructions[0].Signatures = append(proposedTransaction.Instructions[0].Signatures, signature)
	result.ProposedTransaction = proposedTransaction
	resultBuf, err := protobuf.Encode(&result)
	require.Nil(t, err)

	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, resultBuf)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))

	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	err = protobuf.Decode(dataBuf, &result)
	require.Nil(t, err)

	// We can not do this test because the identities have to be compared using
	// the Equal() method.
	//require.Equal(t, result.ProposedTransaction, proposedTransaction)
	require.Equal(t, len(result.ProposedTransaction.Instructions), 1)
	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].SignerIdentities)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].SignerIdentities), 1)
	// This test won't work. But by using Equal() will.
	// require.Equal(t, result.ProposedTransaction.Instructions[0].SignerIdentities[0], identity)
	require.True(t, identity.Equal(&result.ProposedTransaction.Instructions[0].SignerIdentities[0]))

	require.NotEmpty(t, result.ProposedTransaction.Instructions[0].Signatures)
	require.Equal(t, len(result.ProposedTransaction.Instructions[0].Signatures), 1)
	require.Equal(t, result.ProposedTransaction.Instructions[0].Signatures[0], signature)
	// Default NumExecution should be 1
	require.Equal(t, result.NumExecution, uint64(1))

	require.NotEmpty(t, result.InstructionHashes)

	local.WaitDone(genesisMsg.BlockInterval)

	// ------------------------------------------------------------------------
	// 3. Invoke an "execRoot" command
	// ------------------------------------------------------------------------

	ctx = byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: myID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractDeferredID,
				Command:    "execProposedTx",
			},
			SignerCounter: []uint64{3},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	// Need to sleep because we can't predict the output (hence the 'nil')
	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(myID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(myID.Slice()))
	dataBuf, _, _, err = pr.Get(myID.Slice())
	require.Nil(t, err)

	result = byzcoin.DeferredData{}
	protobuf.Decode(dataBuf, &result)
	require.Equal(t, 1, len(result.ExecResult))

	time.Sleep(2 * genesisMsg.BlockInterval)
	pr, err = cl.WaitProof(byzcoin.NewInstanceID(byzcoin.ConfigInstanceID.Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(byzcoin.ConfigInstanceID.Slice()))

	_, valueBuf, _, _, err := pr.KeyValue()
	require.Nil(t, err)

	configResult := byzcoin.ChainConfig{}
	err = protobuf.Decode(valueBuf, &configResult)
	require.Nil(t, err)

	// We check if what we get has the updated values
	require.Equal(t, config.BlockInterval, configResult.BlockInterval)
	require.Equal(t, config.MaxBlockSize, configResult.MaxBlockSize)
	require.Equal(t, config.Roster, configResult.Roster)
	require.Equal(t, config.DarcContractIDs, configResult.DarcContractIDs)

	local.WaitDone(genesisMsg.BlockInterval)
}
