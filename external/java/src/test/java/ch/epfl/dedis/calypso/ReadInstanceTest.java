package ch.epfl.dedis.calypso;

import ch.epfl.dedis.byzcoin.Block;
import ch.epfl.dedis.byzcoin.ByzCoinRPC;
import ch.epfl.dedis.byzcoin.transaction.ClientTransaction;
import ch.epfl.dedis.byzcoin.transaction.Spawn;
import ch.epfl.dedis.integration.TestServerController;
import ch.epfl.dedis.integration.TestServerInit;
import ch.epfl.dedis.lib.SkipBlock;
import ch.epfl.dedis.lib.crypto.Ed25519Pair;
import ch.epfl.dedis.lib.darc.Darc;
import ch.epfl.dedis.lib.darc.Rules;
import ch.epfl.dedis.lib.darc.Signer;
import ch.epfl.dedis.lib.darc.SignerEd25519;
import ch.epfl.dedis.lib.exception.CothorityCommunicationException;
import ch.epfl.dedis.lib.exception.CothorityCryptoException;
import ch.epfl.dedis.lib.network.ServerIdentity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;

import static ch.epfl.dedis.byzcoin.ByzCoinRPCTest.BLOCK_INTERVAL;
import static org.junit.jupiter.api.Assertions.*;

class ReadInstanceTest {
    private CalypsoRPC calypso;
    private WriteInstance w;
    private ReadInstance r;
    private Signer admin;
    private Darc genesisDarc;

    private final static Logger logger = LoggerFactory.getLogger(WriteInstanceTest.class);
    private TestServerController testInstanceController;

    @BeforeEach
    void initAll() throws Exception {
        testInstanceController = TestServerInit.getInstance();
        admin = new SignerEd25519();
        genesisDarc = ByzCoinRPC.makeGenesisDarc(admin, testInstanceController.getRoster());
        genesisDarc.addIdentity("spawn:"+WriteInstance.ContractId, admin.getIdentity(), Rules.OR);
        genesisDarc.addIdentity("spawn:"+ReadInstance.ContractId, admin.getIdentity(), Rules.OR);
        genesisDarc.addIdentity("spawn:"+LTSInstance.ContractId, admin.getIdentity(), Rules.OR);
        genesisDarc.addIdentity("invoke:"+LTSInstance.InvokeCommand, admin.getIdentity(), Rules.OR);

        ByzCoinRPC bc = new ByzCoinRPC(testInstanceController.getRoster(), genesisDarc, BLOCK_INTERVAL);
        for (ServerIdentity si : bc.getRoster().getNodes()) {
            CalypsoRPC.authorize(si, bc.getGenesisBlock().getId());
        }

        calypso = new CalypsoRPC(bc, genesisDarc.getId(), bc.getRoster(),
                Collections.singletonList(admin), Collections.singletonList(1L));
        if (!calypso.checkLiveness()) {
            throw new CothorityCommunicationException("liveness check failed");
        }

        String secret = "this is a secret";
        Document doc = new Document(secret.getBytes(), null, genesisDarc.getBaseId());
        w = new WriteInstance(calypso, genesisDarc.getId(),
                Arrays.asList(admin), Collections.singletonList(2L),
                doc.getWriteData(calypso.getLTS()));
        assertTrue(calypso.getProof(w.getInstance().getId()).matches());

        // ephemeral key cannot be the same as one of the signers
        assertThrows(CothorityCryptoException.class, () -> {
            r = new ReadInstance(calypso, w, Arrays.asList(admin), Collections.singletonList(3L), admin.getPublic());
        });
        Ed25519Pair ephemeralPair = new Ed25519Pair();
        r = new ReadInstance(calypso, w, Arrays.asList(admin), Collections.singletonList(3L), ephemeralPair.point);
        assertTrue(calypso.getProof(r.getInstance().getId()).matches());
    }

    @Test
    void testCopyReader() throws Exception {
        ReadInstance r2 = ReadInstance.fromByzCoin(calypso, r.getInstance().getId());
        assertTrue(calypso.getProof(r2.getInstance().getId()).matches());
    }

    @Test
    void getFromBlock() throws Exception {
        // Crawl through the blockchain and search for ClientTransaction that included a Read command.
        boolean found = false;
        // Need to get the latest version of the genesis-block for the forward-link
        SkipBlock cursor = calypso.getSkipchain().getSkipblock(calypso.getGenesisBlock().getId());

        while (true) {
            Block bcBlock = new Block(cursor);
            for (ClientTransaction ct : bcBlock.getAcceptedClientTransactions()) {
                // Suppose that the spawn instruction for the calypsoRead is in the first element of the array.
                Spawn sp = ct.getInstructions().get(0).getSpawn();
                if (sp != null && sp.getContractID().equals(ReadInstance.ContractId)) {
                    logger.info("Found Reader");
                    ReadData rd = ReadData.fromProto(sp.getArguments().get(0).getValue());
                    assertArrayEquals(r.getRead().toProto().toByteArray(), rd.toProto().toByteArray());
                    found = true;
                }
            }

            // Try to get the next block, but only if there is a forward link.
            if (cursor.getForwardLinks().size() == 0) {
                break;
            } else {
                cursor = calypso.getSkipchain().getSkipblock(cursor.getForwardLinks().get(0).getTo());
            }
        }
        assertTrue(found, "didn't find any read instance");
    }
}
