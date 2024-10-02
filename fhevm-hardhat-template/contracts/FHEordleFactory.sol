// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity ^0.8.20;

import "./FHEordle.sol";
import "fhevm/lib/TFHE.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

/**
 * @title FHEordleFactory
 * @notice This contract is a factory for deploying new instances of the FHEordle game using the minimal proxy pattern (Clones).
 *         It manages multiple instances of the game for different users, tracks game results, and allows minting of rewards
 *         based on the game outcomes.
 * @dev This contract uses OpenZeppelin's Clones library for creating deterministic contract instances and relies on the
 *      FHEordle game logic deployed at a predefined implementation address.
 */
contract FHEordleFactory is Ownable2Step {
    address public creator;

    mapping(address => address) public userLastContract;

    mapping(address => uint32) public gamesWon;
    mapping(address => bool) public claimedWin;
    address private immutable implementation;

    /**
     * @notice Constructor to set the implementation address for game instances.
     * @param _implementation The address of the deployed FHEordle contract used as a template for Clones.
     */
    constructor(address _implementation) Ownable(msg.sender) {
        creator = msg.sender;
        implementation = _implementation;
    }

    /**
     * @notice Creates a new game instance for a user using the specified relayer address and a unique salt.
     * @dev Uses OpenZeppelin's Clones library to deploy a minimal proxy contract. The salt ensures unique deployments.
     * @param _relayerAddr The address of the relayer used for the game.
     * @param salt A unique salt used to determine the deployment address.
     */
    function createGame(address _relayerAddr, bytes32 salt) public {
        address cloneAdd = Clones.cloneDeterministic(implementation, salt);
        FHEordle(cloneAdd).initialize(msg.sender, _relayerAddr, 0);
        userLastContract[msg.sender] = cloneAdd;
    }

    /**
     * @notice Creates a test game instance with a specific word ID for testing purposes.
     * @dev Ensures that a user can only create a single test instance.
     * @param _relayerAddr The address of the relayer used for the game.
     * @param id The word ID to use for testing.
     * @param salt A unique salt used to determine the deployment address.
     */
    function createTest(address _relayerAddr, uint16 id, bytes32 salt) public {
        require(userLastContract[msg.sender] == address(0), "kek");
        address cloneAdd = Clones.cloneDeterministic(implementation, salt);
        FHEordle(cloneAdd).initialize(msg.sender, _relayerAddr, id);
        userLastContract[msg.sender] = cloneAdd;
    }

    /**
     * @notice Checks if the user's last game has been completed.
     * @return True if the game has not started or if the player has either won or used up all guesses.
     */
    function gameNotStarted() public view returns (bool) {
        if (userLastContract[msg.sender] != address(0)) {
            FHEordle game = FHEordle(userLastContract[msg.sender]);
            return game.playerWon() || (game.nGuesses() == 5);
        }
        return true;
    }

    /**
     * @notice Allows a user to mint rewards if they have won a game and the proof has been verified.
     * @dev The user must have a completed game with proof checked and should not have already claimed the reward.
     */
    function mint() public {
        if (userLastContract[msg.sender] != address(0)) {
            address contractAddr = userLastContract[msg.sender];
            FHEordle game = FHEordle(contractAddr);
            require(game.playerWon() && game.proofChecked() && !claimedWin[contractAddr], "has to win and check proof");
            claimedWin[contractAddr] = true;
            gamesWon[msg.sender] += 1;
        }
    }
}
