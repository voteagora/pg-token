// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable-v5/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable-v5/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable-v5/proxy/utils/UUPSUpgradeable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable-v5/utils/ContextUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable-v5/utils/cryptography/EIP712Upgradeable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {VotesUpgradeable} from "@openzeppelin/contracts-upgradeable-v5/governance/utils/VotesUpgradeable.sol";

contract GovernanceToken is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable,
    VotesUpgradeable
{
    using Strings for uint256;
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidOwner(address);
    error InvalidSender(address);
    error InvalidReceiver(address);
    error NonexistentToken(uint256);

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    // Batch Mint
    uint256 private _nextTokenId;
    // Token name
    string private _name;
    // Token symbol
    string private _symbol;
    // Token Owners
    mapping(uint256 tokenId => address) private _owners;
    // Balances of token holdings
    mapping(address owner => uint256) private _balances;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                             PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function initialize(address defaultAdmin, address _timelock, string memory name_, string memory symbol_)
        public
        initializer
    {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __EIP712_init("Protocol Guild Membership", "1");

        _name = name_;
        _symbol = symbol_;

        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(MINTER_ROLE, defaultAdmin);
        _grantRole(UPGRADER_ROLE, defaultAdmin);
        _grantRole(BURNER_ROLE, defaultAdmin);
        _grantRole(BURNER_ROLE, _timelock);
    }

    function balanceOf(address owner) public view virtual returns (uint256) {
        if (owner == address(0)) {
            revert InvalidOwner(address(0));
        }
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view virtual returns (address) {
        return _requireOwned(tokenId);
    }

    function name() public view virtual returns (string memory) {
        return _name;
    }

    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    function tokenURI(uint256 tokenId) public view virtual returns (string memory) {
        _requireOwned(tokenId);

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string.concat(baseURI, tokenId.toString()) : "";
    }

    function mint(address[] calldata recipients) public onlyRole(MINTER_ROLE) {
        uint256 startTokenId = _nextTokenId;
        uint256 numRecipients = recipients.length;

        for (uint256 i = 0; i < numRecipients; i++) {
            _safeMint(recipients[i], startTokenId + i);
        }

        _nextTokenId = startTokenId + numRecipients;
    }

    function burn(uint256 tokenId) public {
        require(
            hasRole(BURNER_ROLE, _msgSender()) || ownerOf(tokenId) == _msgSender(),
            "Caller must be owner or have BURNER_ROLE"
        );
        _update(address(0), tokenId);
    }

    function burn(uint256[] calldata tokenIds) public onlyRole(BURNER_ROLE) {
        uint256 numTokens = tokenIds.length;
        for (uint256 i = 0; i < numTokens; i++) {
            burn(tokenIds[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overridden in child contracts.
     */
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }

    /**
     * @dev Returns the owner of the `tokenId`. Does NOT revert if token doesn't exist
     *
     */
    function _ownerOf(uint256 tokenId) internal view virtual returns (address) {
        return _owners[tokenId];
    }

    /**
     * @dev Transfers `tokenId` from its current owner to `to`, or alternatively mints (or burns) if the current owner
     * (or `to`) is the zero address. Returns the owner of the `tokenId` before the update.
     *
     * Emits a {Transfer} event.
     *
     */
    function _update(address to, uint256 tokenId) internal virtual returns (address) {
        address from = _ownerOf(tokenId);

        // Execute the update
        if (from != address(0)) {
            unchecked {
                _balances[from] -= 1;
            }
        }

        if (to != address(0)) {
            unchecked {
                _balances[to] += 1;
            }
        }

        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);

        _transferVotingUnits(from, to, 1);

        return from;
    }

    /**
     * @dev Mints `tokenId` and transfers it to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - `to` cannot be the zero address.
     *
     * Emits a {Transfer} event.
     */
    function _mint(address to, uint256 tokenId) internal {
        if (to == address(0)) {
            revert InvalidReceiver(address(0));
        }
        address previousOwner = _update(to, tokenId);
        if (previousOwner != address(0)) {
            revert InvalidSender(address(0));
        }
    }

    function _safeMint(address to, uint256 tokenId) internal {
        _mint(to, tokenId);
    }

    /**
     * @dev Reverts if the `tokenId` doesn't have a current owner (it hasn't been minted, or it has been burned).
     * Returns the owner.
     *
     * Overrides to ownership logic should be done to {_ownerOf}.
     */
    function _requireOwned(uint256 tokenId) internal view returns (address) {
        address owner = _ownerOf(tokenId);
        if (owner == address(0)) {
            revert NonexistentToken(tokenId);
        }
        return owner;
    }

    /**
     * @dev Returns the balance of `account`.
     *
     * WARNING: Overriding this function will likely result in incorrect vote tracking.
     */
    function _getVotingUnits(address account) internal view virtual override returns (uint256) {
        return balanceOf(account);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
