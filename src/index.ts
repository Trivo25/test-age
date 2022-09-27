import {
  Field,
  Experimental,
  CircuitValue,
  PublicKey,
  UInt32,
  Poseidon,
  prop,
  PrivateKey,
  Signature,
  isReady,
  shutdown,
} from 'snarkyjs';

await isReady;

class User extends CircuitValue {
  @prop publicKey: PublicKey;
  @prop age: UInt32;

  constructor(publicKey: PublicKey, age: UInt32) {
    super();
    this.publicKey = publicKey;
    this.age = age;
  }

  hash(): Field {
    return Poseidon.hash(this.toFields());
  }
}

let KYCProgram = Experimental.ZkProgram({
  publicInput: Field,

  methods: {
    verifyAge: {
      privateInputs: [User],

      method(userHash: Field, user: User) {
        user.age.assertGte(UInt32.from(21));
        // we have to constraint the public input to the users hash
        userHash.assertEquals(user.hash());
      },
    },
  },
});

class MerkleWitness extends Experimental.MerkleWitness(3) {}

const CivicPrivateKey = PrivateKey.random();
const CivicPublicKey = CivicPrivateKey.toPublicKey();

const KYCTree = new Experimental.MerkleTree(3);

let user1 = new User(PrivateKey.random().toPublicKey(), UInt32.from(15));
let user2 = new User(PrivateKey.random().toPublicKey(), UInt32.from(18));
let user3 = new User(PrivateKey.random().toPublicKey(), UInt32.from(36));
let user4 = new User(PrivateKey.random().toPublicKey(), UInt32.from(21));

KYCTree.setLeaf(0n, user1.hash());
KYCTree.setLeaf(1n, user2.hash());
KYCTree.setLeaf(2n, user3.hash());
KYCTree.setLeaf(3n, user4.hash());

console.log('compiling...');
await KYCProgram.compile();

// the user creates this proof
console.log('user3 creates an age proof...');
let proofForUser3 = await KYCProgram.verifyAge(user3.hash(), user3);

// the verifier knows this
let userHash = user3.hash();
let merkleWitnessForUser3 = new MerkleWitness(KYCTree.getWitness(2n));
let rootSignedByCivic = Signature.create(CivicPrivateKey, [KYCTree.getRoot()]);

// the verifier checks
console.log('verifier checks if age proof is valid...');
// checks the users hash is signed by Civic
rootSignedByCivic.verify(CivicPublicKey, [KYCTree.getRoot()]).assertTrue();
// checks that the proof has been created with the users hash as public input
proofForUser3.publicInput.assertEquals(userHash);
// verifies the proof
proofForUser3.verify();
// verifies that the user is part of the merkle tree
merkleWitnessForUser3.calculateRoot(userHash).assertEquals(KYCTree.getRoot());
console.log('proof is valid!');
//process.exit(0);
shutdown();
