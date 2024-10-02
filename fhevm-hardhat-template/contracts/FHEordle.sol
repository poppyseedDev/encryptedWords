// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "fhevm/gateway/GatewayCaller.sol";

/**
 * @title FHEordle
 * @notice This contract implements a fully homomorphic encryption (FHE) version of the classic word game, similar to "Wordle".
 *         It allows players to submit encrypted guesses and receive feedback on whether their guess is correct.
 *         The contract is integrated with a secure gateway that handles decryption requests to ensure confidentiality.
 * @dev This contract leverages the TFHE library for encryption operations and the MerkleProof library for verifying word sets.
 *      The game state and logic are managed using various public and private variables.
 */
contract FHEordle is Ownable2Step, GatewayCaller, Initializable {
    /// Constants
    bytes32 public constant root = 0x918fd5f641d6c8bb0c5e07a42f975969c2575250dc3fb743346d1a3c11728bdd;
    bytes32 public constant rootAllowed = 0xd3e7a12d252dcf5de57a406f0bd646217ec1f340bad869182e5b2bfadd086993;
    uint16 public constant wordSetSz = 5757;

    /// Initialization variables
    address public playerAddr;
    address public relayerAddr;
    uint16 public testFlag;

    /// Secret Word Variables
    euint16 private word1Id;
    euint8[5] private word1Letters;
    euint32 private word1LettersMask;
    uint32 public word1;

    /// Player Guess variables
    uint8 public nGuesses;
    uint32[5] public guessHist;

    /// Game state variables
    bool public wordSubmitted;
    bool public gameStarted;
    bool public playerWon;
    bool public proofChecked;

    // Storage values for callbacks
    uint8 public l0;
    uint8 public l1;
    uint8 public l2;
    uint8 public l3;
    uint8 public l4;
    bytes32[] public storedProof;

    //events
    event WordSubmitted(address indexed player, uint32 word);
    event GuessDecryptionRequested(uint8 guessN, uint256 timestamp);
    event PlayerWon(address indexed player);
    event GuessDecrypted(uint8 decryptedEqMask, uint32 decryptedLetterMask);
    event WinDecryptionRequested(uint8 guessN, uint256 timestamp);
    event WordRevealRequested(address indexed player, uint256 timestamp);

    constructor() Ownable(msg.sender) {}

    function initialize(address _playerAddr, address _relayerAddr, uint16 _testFlag) external initializer {
        relayerAddr = _relayerAddr;
        playerAddr = _playerAddr;
        testFlag = _testFlag;
        if (testFlag > 0) {
            word1Id = TFHE.asEuint16(_testFlag);
        } else {
            word1Id = TFHE.rem(TFHE.randEuint16(), wordSetSz);
        }
        word1LettersMask = TFHE.asEuint32(0);
        for (uint8 i = 0; i < 5; i++) {
            guessHist[i] = 0;
        }
        nGuesses = 0;
        wordSubmitted = false;
        gameStarted = false;
        playerWon = false;
        proofChecked = false;
        word1 = 0;
    }

    // function getWord1Id(
    //     bytes32 publicKey,
    //     bytes calldata signature
    // ) public view virtual onlySignedPublicKey(publicKey, signature) onlyRelayer returns (bytes memory) {
    //     return TFHE.reencrypt(word1Id, publicKey);
    // }

    function getWord1Id() public view virtual onlyRelayer returns (euint16) {
        return (word1Id); //publicKey);
    }

    function submitWord1(
        bytes calldata el0,
        bytes calldata el1,
        bytes calldata el2,
        bytes calldata el3,
        bytes calldata el4
    ) public {
        // Decode the bytes to uint8
        euint8 _l0 = TFHE.asEuint8(abi.decode(el0, (uint8)));
        euint8 _l1 = TFHE.asEuint8(abi.decode(el1, (uint8)));
        euint8 _l2 = TFHE.asEuint8(abi.decode(el2, (uint8)));
        euint8 _l3 = TFHE.asEuint8(abi.decode(el3, (uint8)));
        euint8 _l4 = TFHE.asEuint8(abi.decode(el4, (uint8)));

        // Call the overloaded submitWord1 with euint8 values
        submitWord1(_l0, _l1, _l2, _l3, _l4);
    }

    function submitWord1(euint8 _l0, euint8 _l1, euint8 _l2, euint8 _l3, euint8 _l4) public onlyRelayer {
        require(!wordSubmitted, "word submitted");
        word1Letters[0] = _l0;
        word1Letters[1] = _l1;
        word1Letters[2] = _l2;
        word1Letters[3] = _l3;
        word1Letters[4] = _l4;
        word1LettersMask = TFHE.or(
            TFHE.shl(TFHE.asEuint32(1), word1Letters[0]),
            TFHE.or(
                TFHE.shl(TFHE.asEuint32(1), word1Letters[1]),
                TFHE.or(
                    TFHE.shl(TFHE.asEuint32(1), word1Letters[2]),
                    TFHE.or(TFHE.shl(TFHE.asEuint32(1), word1Letters[3]), TFHE.shl(TFHE.asEuint32(1), word1Letters[4]))
                )
            )
        );
        wordSubmitted = true;
        gameStarted = true;
    }

    function guessWord1(uint32 word, bytes32[] calldata proof) public onlyPlayer {
        require(gameStarted, "game not started");
        require(nGuesses < 5, "cannot exceed five guesses!");

        uint8 zeroIndex = 0;
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(zeroIndex, word))));
        require(MerkleProof.verify(proof, rootAllowed, leaf), "Invalid word");
        guessHist[nGuesses] = word;
        nGuesses += 1;
    }

    function getEqMask(uint8 guessN) internal returns (euint8) {
        uint32 word = guessHist[guessN];
        uint8 _l0 = uint8((word) % 26);
        uint8 _l1 = uint8((word / 26) % 26);
        uint8 _l2 = uint8((word / 26 / 26) % 26);
        uint8 _l3 = uint8((word / 26 / 26 / 26) % 26);
        uint8 _l4 = uint8((word / 26 / 26 / 26 / 26) % 26);
        euint8 g0 = TFHE.asEuint8(TFHE.eq(word1Letters[0], _l0));
        euint8 g1 = TFHE.asEuint8(TFHE.eq(word1Letters[1], _l1));
        euint8 g2 = TFHE.asEuint8(TFHE.eq(word1Letters[2], _l2));
        euint8 g3 = TFHE.asEuint8(TFHE.eq(word1Letters[3], _l3));
        euint8 g4 = TFHE.asEuint8(TFHE.eq(word1Letters[4], _l4));
        euint8 eqMask = TFHE.or(
            TFHE.shl(g0, 0),
            TFHE.or(TFHE.shl(g1, 1), TFHE.or(TFHE.shl(g2, 2), TFHE.or(TFHE.shl(g3, 3), TFHE.shl(g4, 4))))
        );
        return eqMask;
    }

    function getLetterMaskGuess(uint8 guessN) internal returns (euint32) {
        uint32 word = guessHist[guessN];
        uint32 _l0 = (word) % 26;
        uint32 _l1 = (word / 26) % 26;
        uint32 _l2 = (word / 26 / 26) % 26;
        uint32 _l3 = (word / 26 / 26 / 26) % 26;
        uint32 _l4 = (word / 26 / 26 / 26 / 26) % 26;
        uint32 base = 1;
        uint32 letterMask = (base << _l0) | (base << _l1) | (base << _l2) | (base << _l3) | (base << _l4);
        return TFHE.and(word1LettersMask, TFHE.asEuint32(letterMask));
    }

    // function getGuess(uint8 guessN) public view onlyPlayer returns (uint8, uint32) {
    //     require(guessN < nGuesses, "cannot exceed nGuesses");
    //     euint8 eqMask = getEqMask(guessN);
    //     euint32 letterMaskGuess = getLetterMaskGuess(guessN);
    //     return (TFHE.decrypt(eqMask), TFHE.decrypt(letterMaskGuess));
    // }

    function getGuess(uint8 guessN) public onlyPlayer {
        require(guessN < nGuesses, "cannot exceed nGuesses");

        // Get the encrypted values
        euint8 eqMask = getEqMask(guessN);
        euint32 letterMaskGuess = getLetterMaskGuess(guessN);

        // Prepare an array of ciphertexts to decrypt
        uint256[] memory cts = new uint256[](2);
        cts[0] = Gateway.toUint256(eqMask);
        cts[1] = Gateway.toUint256(letterMaskGuess);

        // Emit an event for easier tracking of decryption requests
        emit GuessDecryptionRequested(guessN, block.timestamp);

        // Request decryption via the gateway
        Gateway.requestDecryption(cts, this.callbackGuess.selector, 0, block.timestamp + 100, false);
    }

    function callbackGuess(
        uint256 /*requestID*/,
        uint8 decryptedEqMask,
        uint32 decryptedLetterMask
    ) public onlyGateway returns (uint8, uint32) {
        // emit GuessDecrypted(decryptedEqMask, decryptedLetterMask);
        return (decryptedEqMask, decryptedLetterMask);
    }

    // function claimWin(uint8 guessN) public onlyPlayer {
    //     euint8 fullMask = TFHE.asEuint8(31);
    //     bool compare = TFHE.decrypt(TFHE.eq(fullMask, getEqMask(guessN)));
    //     if (compare) {
    //         playerWon = true;
    //     }
    // }

    function claimWin(uint8 guessN) public onlyPlayer {
        euint8 fullMask = TFHE.asEuint8(31);
        ebool is_equal = TFHE.eq(fullMask, getEqMask(guessN));
        // Request decryption via the Gateway
        uint256[] memory cts = new uint256[](1);
        cts[0] = Gateway.toUint256(is_equal);
        emit WinDecryptionRequested(guessN, block.timestamp);

        Gateway.requestDecryption(cts, this.callbackClaimWin.selector, 0, block.timestamp + 100, false);
    }

    function callbackClaimWin(uint256 /*requestID*/, bool decryptedComparison) public onlyGateway {
        // Handle the decrypted comparison result
        if (decryptedComparison) {
            playerWon = true;
        }
    }

    // function revealWord() public view onlyPlayer returns (uint8, uint8, uint8, uint8, uint8) {
    //     assert(nGuesses == 5 || playerWon);
    //     uint8 l0 = TFHE.decrypt(word1Letters[0]);
    //     uint8 l1 = TFHE.decrypt(word1Letters[1]);
    //     uint8 l2 = TFHE.decrypt(word1Letters[2]);
    //     uint8 l3 = TFHE.decrypt(word1Letters[3]);
    //     uint8 l4 = TFHE.decrypt(word1Letters[4]);
    //     return (l0, l1, l2, l3, l4);
    // }

    function revealWord() public onlyPlayer {
        // Prepare the ciphertext array for the five letters
        uint256[] memory cts = new uint256[](5);

        for (uint8 i = 0; i < 5; i++) {
            cts[i] = Gateway.toUint256(word1Letters[i]);
        }

        emit WordRevealRequested(msg.sender, block.timestamp);
        // Request decryption of the letters
        Gateway.requestDecryption(cts, this.callbackRevealWord.selector, 0, block.timestamp + 100, false);
    }

    function callbackRevealWord(
        uint256 /*requestID*/,
        uint8 _l0,
        uint8 _l1,
        uint8 _l2,
        uint8 _l3,
        uint8 _l4
    ) public onlyPlayer returns (uint8, uint8, uint8, uint8, uint8) {
        l0 = _l0;
        l1 = _l1;
        l2 = _l2;
        l3 = _l3;
        l4 = _l4;
        // Handle the decrypted word letters here (e.g., emit events or store values)
        return (l0, l1, l2, l3, l4); // Optionally emit an event
    }

    function revealWordAndStore() public onlyPlayer {
        require(l0 != 0 || l1 != 0 || l2 != 0 || l3 != 0 || l4 != 0, "Word not revealed yet");

        word1 =
            uint32(l0) +
            uint32(l1) *
            26 +
            uint32(l2) *
            26 *
            26 +
            uint32(l3) *
            26 *
            26 *
            26 +
            uint32(l4) *
            26 *
            26 *
            26 *
            26;
    }

    // function checkProof(bytes32[] calldata proof) public onlyRelayer {
    //     assert(nGuesses == 5 || playerWon);
    //     uint16 wordId = TFHE.decrypt(word1Id);
    //     bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(wordId, word1))));
    //     if (MerkleProof.verify(proof, root, leaf)) {
    //         proofChecked = true;
    //     }
    // }

    function checkProof(bytes32[] calldata proof) public onlyRelayer {
        // Store the proof for use in the callback
        storedProof = proof;

        // Prepare the ciphertext for word1Id
        uint256[] memory cts = new uint256[](1);
        cts[0] = Gateway.toUint256(word1Id);

        // Request decryption of word1Id
        Gateway.requestDecryption(cts, this.callbackCheckProof.selector, 0, block.timestamp + 100, false);
    }

    function callbackCheckProof(uint256 /*requestID*/, uint16 decryptedWordId) public onlyGateway {
        // Handle the decrypted wordId and check the proof
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(decryptedWordId, word1))));
        if (MerkleProof.verify(storedProof, root, leaf)) {
            proofChecked = true;
        }
    }

    modifier onlyRelayer() {
        require(msg.sender == relayerAddr);
        _;
    }

    modifier onlyPlayer() {
        require(msg.sender == playerAddr);
        _;
    }
}
