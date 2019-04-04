package testdata

import (
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
)

// PROTOSTART
// type :skipchain.SkipBlockID:bytes
// type :byzcoin.InstanceID:bytes
// package testdata;
//
// option java_package = "ch.epfl.dedis.lib.proto";
// option java_outer_classname = "TestData";

// TestStore is used to store test-structures. If it is called
// with null pointers, nothing is stored, and only the currently
// stored data is returned.
// This will not be saved to disk.
type TestStore struct {
	ByzCoinID  skipchain.SkipBlockID `protobuf:"opt"`
	SpawnerIID byzcoin.InstanceID    `protobuf:"opt"`
}
