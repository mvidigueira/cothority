import ByzCoinRPC from "../../byzcoin-rpc";
import ClientTransaction, {Argument, Instruction} from "../../client-transaction";
import Proof from "../../proof";
import DarcInstance from "../darc-instance";
import Signer from "../../../darc/signer";
import SpawnerInstance from "../spawner-instance";
import CredentialInstance from "../credentials-instance";
import { Point, curve, Scalar } from "@dedis/kyber";
import Instance from "../../instance";
import { Log } from '../../../log';
import { PopPartyStruct, FinalStatement } from "./proto";
import { sign } from './ring-signature';

const ed25519 = curve.newCurve('edwards25519');

export class PopPartyInstance {
    static readonly contractID = "popParty";
    static readonly PreBarrier = 1;
    static readonly Scanning = 2;
    static readonly Finalized = 3;

    private rpc: ByzCoinRPC;
    private instance: Instance;
    public tmpAttendees: Point[] = [];
    public popPartyStruct: PopPartyStruct;

    constructor(public bc: ByzCoinRPC, inst: Instance) {
        this.rpc = bc;
        this.instance = inst;
        this.popPartyStruct = PopPartyStruct.decode(this.instance.data);
    }

    async fetchOrgKeys(): Promise<Point[]> {
        let piDarc = await DarcInstance.fromByzcoin(this.bc, this.instance.darcID);
        let exprOrgs = piDarc.darc.rules.list.find(l => l.action == "invoke:finalize").expr;
        let orgDarcs = exprOrgs.toString().split(" | ");
        let orgPers: Point[] = [];
        for (let i = 0; i < orgDarcs.length; i++) {
            // Remove leading "darc:" from expression
            const orgDarc = orgDarcs[i].substr(5);
            const orgCred = SpawnerInstance.credentialIID(Buffer.from(orgDarc, 'hex'));
            Log.lvl2("Searching personhood-identity of organizer", orgDarc, orgCred);
            const cred = await CredentialInstance.fromByzcoin(this.bc, orgCred);
            const credPers = cred.getAttribute("personhood", "ed25519");
            if (!credPers) {
                throw new Error("found organizer without personhood credential");
            }

            const pub = ed25519.point();
            pub.unmarshalBinary(credPers);

            orgPers.push(pub);
        }

        return orgPers;
    }

    getFinalStatement(): FinalStatement {
        if (this.popPartyStruct.state !== PopPartyInstance.Finalized) {
            throw new Error("this party is not finalized yet");
        }

        return new FinalStatement({
            desc: this.popPartyStruct.description,
            attendees: this.popPartyStruct.attendees,
        });
    }

    async activateBarrier(org: Signer): Promise<number> {
        if (this.popPartyStruct.state !== PopPartyInstance.PreBarrier) {
            return Promise.reject("barrier point has already been passed");
        }

        const instr = Instruction.createInvoke(
            this.instance.id,
            PopPartyInstance.contractID,
            "barrier",
            [],
        );
        await instr.updateCounters(this.rpc, [org]);

        const ctx = new ClientTransaction({ instructions: [instr] });
        ctx.signWith([org]);

        await this.bc.sendTransactionAndWait(ctx);
        await this.update();

        return this.popPartyStruct.state;
    }

    addAttendee(attendee: Point): void {
        if (this.popPartyStruct.state !== PopPartyInstance.Scanning) {
            throw new Error("party is not in attendee-adding mode");
        }

        if (this.tmpAttendees.findIndex(pub => pub.equal(attendee)) >= 0) {
            throw new Error("already have this attendee");
        }

        this.tmpAttendees.push(attendee);
    }

    delAttendee(attendee: Point): number {
        if (this.popPartyStruct.state !== PopPartyInstance.Scanning) {
            throw new Error("party is not in attendee-adding mode");
        }

        let i = this.tmpAttendees.findIndex(pub => pub.equal(attendee));
        if (i == -1) {
            throw new Error("unknown attendee");
        }
        this.tmpAttendees.splice(i, 1);
        return this.tmpAttendees.length;
    }

    async finalize(org: Signer): Promise<number> {
        if (this.popPartyStruct.state !== PopPartyInstance.Scanning) {
            return Promise.reject("party did not pass barrier-point yet");
        }

        const keys = this.tmpAttendees
            .map(p => p.marshalBinary())
            .sort((a, b) => Buffer.compare(a, b));

        this.popPartyStruct.updateAttendes(keys);

        const instr = Instruction.createInvoke(
            this.instance.id,
            PopPartyInstance.contractID,
            "finalize",
            [new Argument({ name: "attendees", value: this.popPartyStruct.attendees.toBytes() })],
        )
        await instr.updateCounters(this.rpc, [org]);

        const ctx = new ClientTransaction({ instructions: [instr] });
        ctx.signWith([org]);

        await this.bc.sendTransactionAndWait(ctx);
        await this.update();

        return this.popPartyStruct.state;
    }

    async update(): Promise<PopPartyInstance> {
        const proof = await this.bc.getProof(this.instance.id);
        if (!proof.matches()) {
            throw new Error('fail to get a matching proof');
        }

        this.instance = Instance.fromProof(proof);
        this.popPartyStruct = PopPartyStruct.decode(this.instance.data);

        if (this.popPartyStruct.state === PopPartyInstance.Scanning &&
            this.tmpAttendees.length === 0) {
            this.tmpAttendees = await this.fetchOrgKeys();
        }

        return this;
    }

    /**
     * Mine coins for a person using a coin instance ID
     */
    async mine(secret: Scalar, coinID?: Buffer): Promise<void> {
        if (this.popPartyStruct.state != PopPartyInstance.Finalized) {
            return Promise.reject("cannot mine on a non-finalized party");
        }

        const lrs = await sign(Buffer.from("mine"), this.popPartyStruct.attendees.keys, this.instance.id, secret);
        const args = [
            new Argument({ name: "lrs", value: lrs.encode() }),
            new Argument({ name: "coinIID", value: coinID })
        ];

        const instr = Instruction.createInvoke(
            this.instance.id,
            PopPartyInstance.contractID,
            "mine",
            args,
        );
        // TODO: counter needs to be set but no signer ??
        const ctx = new ClientTransaction({ instructions: [instr] });
        // TODO: ctx needs to be signed but no signer ??

        await this.bc.sendTransactionAndWait(ctx);
        await this.update();
    }

    public static fromProof(rpc: ByzCoinRPC, proof: Proof): PopPartyInstance {
        return new PopPartyInstance(rpc, Instance.fromProof(proof));
    }

    public static async fromByzcoin(bc: ByzCoinRPC, iid: Buffer): Promise<PopPartyInstance> {
        const p = await bc.getProof(iid);
        if (!p.matches()) {
            throw new Error('fail to get a matching proof');
        }

        return PopPartyInstance.fromProof(bc, p);
    }
}
