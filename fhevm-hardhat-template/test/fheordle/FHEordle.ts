import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import { expect } from "chai";
import { ethers } from "hardhat";

import { FHEordle, FHEordleFactory, FHEordle__factory } from "../../types";
import { createInstances } from "../instance";
import { getSigners, initSigners } from "../signers";
import { createTransaction } from "../utils";
import { deployFHEordleFixture } from "./FHEordle.fixture";
import { VALID_WORDS } from "./validWordsList";
import { WORDS } from "./wordslist";

export function genProofAndRoot(values: any, key: any, encoding: string[]): [string, string[]] {
  const tree = StandardMerkleTree.of(values, encoding);
  const root = tree.root;
  for (const [i, v] of tree.entries()) {
    if (v[1] == key[1]) {
      const proof = tree.getProof(i);
      return [root, proof];
    }
  }
  return ["", []];
}

export const wordToNumber = (word: string) => {
  return (
    word.charCodeAt(0) -
    97 +
    (word.charCodeAt(1) - 97) * 26 +
    (word.charCodeAt(2) - 97) * 26 * 26 +
    (word.charCodeAt(3) - 97) * 26 * 26 * 26 +
    (word.charCodeAt(4) - 97) * 26 * 26 * 26 * 26
  );
};

describe("FHEordle", function () {
  // before(async function () {
  //   await initSigners();
  //   this.signers = await getSigners();
  // });

  before(async function () {
    await initSigners();
    this.signers = await getSigners();
  });

  beforeEach(async function () {
    const [contract, factoryContract] = await deployFHEordleFixture();
    this.factoryContractAddress = await factoryContract.getAddress();
    this.factoryContract = factoryContract;
    this.contractAddress = await contract.getAddress();
    this.contract = contract;

    // Create contract instances
    this.instances = await createInstances(this.signers);
  });

  it("should initialize encrypted word ID", async function () {
    // const input = this.instances.bob.createEncryptedInput(this.contractAddress, this.signers.bob.address);
    // input.add16(3);
    // const encryptedWordId = input.encrypt();
    const salt = ethers.encodeBytes32String("test_salt");

    const creategameTx = await this.factoryContract.createTest(this.signers.bob.address, 3, salt);
    await creategameTx.wait();

    // Retrieve the new contract address
    const gameAddress = await this.factoryContract.userLastContract(this.signers.alice.address);
    // const fheordleGame = this.factoryContract.connect(gameAddress, this.signers.alice);
    const fheordleGame = await ethers.getContractAt("FHEordle", gameAddress, this.signers.bob);

    const wordId = await fheordleGame.getWord1Id();

    // Generate the private and public key, used for the reencryption
    const { publicKey: publicKeyBob, privateKey: privateKeyBob } = this.instances.bob.generateKeypair();

    const eip712 = this.instances.bob.createEIP712(publicKeyBob, this.contractAddress);
    // This function will call the gateway and decrypt the received value with the provided private key
    const signatureBob = await this.signers.alice.signTypedData(
      eip712.domain,
      { Reencrypt: eip712.types.Reencrypt },
      eip712.message,
    );
    const wordIdBob = await this.instances.alice.reencrypt(
      wordId,
      privateKeyBob,
      publicKeyBob,
      signatureBob.replace("0x", ""),
      this.contractAddress,
      this.signers.bob.address,
    );
    expect(wordIdBob).to.equal(3);
  });

  // it("should correctly decrypt and submit a word", async function () {
  //   const { bob } = this.signers;

  //   const wordToEncrypt = [17, 4, 17, 20, 13]; // Representing the word "rerun"
  //   const encryptedWord = wordToEncrypt.map((letter) => this.instances.bob.encrypt8(letter));

  //   const txSubmit = await this.contract
  //     .connect(bob)
  //     ["submitWord1(bytes,bytes,bytes,bytes,bytes)"](...encryptedWord.map((e) => e.toBytes()));
  //   await txSubmit.wait();

  //   const wordSubmitted = await this.contract.wordSubmitted();
  //   expect(wordSubmitted);
  // });

  // it("should return correct masks", async function () {
  //   // word
  //   // 0 1 3 2 4
  //   // 0 + 1*26 + 3*26*26 + 2*26*26*26 + 4*26*26*26*26
  //   // 1865110
  //   // id = 3

  //   const wordsList = [];
  //   for (let i = 0; i < WORDS.length; i++) {
  //     wordsList.push([i, wordToNumber(WORDS[i])]);
  //   }
  //   const [_root, proof] = genProofAndRoot(wordsList, [3, wordToNumber(WORDS[3])], ["uint16", "uint32"]);
  //   expect(StandardMerkleTree.verify(_root, ["uint16", "uint32"], [3, wordToNumber(WORDS[3])], proof)).to.equal(true);
  //   console.log(_root);
  //   const ourWord = wordsList[3][1]; // "about"

  //   const validWordsList = [];
  //   for (let i = 0; i < VALID_WORDS.length; i++) {
  //     validWordsList.push([0, wordToNumber(VALID_WORDS[i])]);
  //   }
  //   const [_validRoot, proofValid] = genProofAndRoot(
  //     validWordsList,
  //     [0, wordToNumber(VALID_WORDS[1])],
  //     ["uint8", "uint32"],
  //   );
  //   expect(
  //     StandardMerkleTree.verify(_validRoot, ["uint8", "uint32"], [0, wordToNumber(VALID_WORDS[1])], proofValid),
  //   ).to.equal(true);
  //   console.log(_validRoot);

  //   const contractInitializerFactory = await ethers.getContractFactory("FHEordle");
  //   const contractInitializer: FHEordle = await contractInitializerFactory.connect(this.signers.alice).deploy();
  //   const contractInitializerAddress = await contractInitializer.getAddress();

  //   const fheordleFactoryFactory = await ethers.getContractFactory("FHEordleFactory");
  //   const factoryContract: FHEordleFactory = await fheordleFactoryFactory
  //     .connect(this.signers.alice)
  //     .deploy(contractInitializerAddress);
  //   await factoryContract.waitForDeployment();
  //   const txDeploy = await createTransaction(
  //     factoryContract.createTest,
  //     this.signers.bob.address,
  //     3,
  //     "0xf172873c63909462ac4de545471fd3ad3e9eeadeec4608b92d16ce6b500704cc",
  //   );
  //   await txDeploy.wait();

  //   const testContractAddress = await factoryContract.userLastContract(this.signers.alice.address);
  //   const contract: FHEordle = FHEordle__factory.connect(testContractAddress).connect(this.signers.alice);

  //   this.contractAddress = await contract.getAddress();
  //   this.instances = await createInstances(this.contractAddress, ethers, this.signers);

  //   // get word id (Bob-Relayer)
  //   {
  //     const bobContract = contract.connect(this.signers.bob);
  //     const token = this.instances.bob.getTokenSignature(this.contractAddress)!;
  //     const tx1 = await bobContract.getWord1Id(token.publicKey, token.signature);
  //     const word1Id = this.instances.bob.decrypt(this.contractAddress, tx1);
  //     expect(word1Id).to.equal(3);
  //   }

  //   console.log("submit word");

  //   // submit word letters (Bob-Relayer)
  //   {
  //     const bobContract = contract.connect(this.signers.bob);
  //     const l0 = ourWord % 26;
  //     const l1 = Math.floor(ourWord / 26) % 26;
  //     const l2 = Math.floor(ourWord / 26 / 26) % 26;
  //     const l3 = Math.floor(ourWord / 26 / 26 / 26) % 26;
  //     const l4 = Math.floor(ourWord / 26 / 26 / 26 / 26) % 26;
  //     console.log(l0, l1, l2, l3, l4);
  //     const encl0 = this.instances.bob.encrypt8(l0);
  //     const encl1 = this.instances.bob.encrypt8(l1);
  //     const encl2 = this.instances.bob.encrypt8(l2);
  //     const encl3 = this.instances.bob.encrypt8(l3);
  //     const encl4 = this.instances.bob.encrypt8(l4);
  //     const tx1 = await createTransaction(
  //       bobContract["submitWord1(bytes,bytes,bytes,bytes,bytes)"],
  //       encl0,
  //       encl1,
  //       encl2,
  //       encl3,
  //       encl4,
  //     );
  //     await tx1.wait();
  //   }

  //   {
  //     const wordSubmitted = await contract.wordSubmitted();
  //     expect(wordSubmitted);
  //   }

  //   {
  //     const gameStarted = await contract.gameStarted();
  //     expect(gameStarted);
  //   }

  //   console.log("guess 1");

  //   //guess n.1
  //   {
  //     // "rerun"
  //     const l0 = 17;
  //     const l1 = 4;
  //     const l2 = 17;
  //     const l3 = 20;
  //     const l4 = 13;
  //     const word = l0 + 26 * (l1 + 26 * (l2 + 26 * (l3 + 26 * l4)));
  //     const [_vR, proof] = genProofAndRoot(validWordsList, [0, word], ["uint8", "uint32"]);
  //     const tx1 = await createTransaction(contract.guessWord1, word, proof);
  //     await tx1.wait();
  //   }

  //   //number of guesses
  //   {
  //     const nguess = await contract.nGuesses();
  //     expect(nguess).to.equal(1);
  //   }

  //   //check guess
  //   {
  //     const [eqMask, letterMask] = await contract.getGuess(0);
  //     expect(eqMask).to.equal(8);
  //     expect(letterMask).to.equal(1 << 20);
  //   }

  //   console.log("guess 2");
  //   // guess 2
  //   {
  //     // "about"
  //     const l0 = 0;
  //     const l1 = 1;
  //     const l2 = 14;
  //     const l3 = 20;
  //     const l4 = 19;
  //     const word = l0 + 26 * (l1 + 26 * (l2 + 26 * (l3 + 26 * l4)));
  //     const [_validRoot, proof] = genProofAndRoot(validWordsList, [0, word], ["uint8", "uint32"]);
  //     const tx1 = await createTransaction(contract.guessWord1, word, proof);
  //     await tx1.wait();
  //   }

  //   // number of guesses
  //   {
  //     const nguess = await contract.nGuesses();
  //     expect(nguess).to.equal(2);
  //   }

  //   // get guess
  //   {
  //     const [eqMask, letterMask] = await contract.getGuess(1);
  //     expect(eqMask).to.equal(31);
  //     expect(letterMask).to.equal(1589251);
  //   }

  //   console.log("claim win");
  //   // claim win
  //   {
  //     const tx1 = await createTransaction(contract.claimWin, 1);
  //     await tx1.wait();
  //     const hasWon = await contract.playerWon();
  //     expect(hasWon);
  //   }

  //   console.log("reveal word");
  //   // reveal word
  //   {
  //     const tx1 = await createTransaction(contract.revealWordAndStore);
  //     await tx1.wait();
  //     const word = await contract.word1();
  //     expect(word).to.equal(ourWord);
  //   }

  //   console.log("check proof");
  //   // check proof
  //   {
  //     const bobContract = contract.connect(this.signers.bob);
  //     const tx1 = await createTransaction(bobContract.checkProof, proof);
  //     await tx1.wait();
  //     const proofChecked = await contract.proofChecked();
  //     expect(proofChecked);
  //   }
  // }).timeout(180000);
});
