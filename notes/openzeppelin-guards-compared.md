# OpenZeppelin Guards, Compared Against My Lab Versions

- **Status:** study note — 2026-11-16
- **What I read:** the actual source files in
  `OpenZeppelin/openzeppelin-contracts` at commit
  `7df9390d5989ea2cb7a70ad93f96245d8a82574e` (default branch head on the
  day I read it): `contracts/utils/ReentrancyGuard.sol` (last updated
  v5.5.0), `contracts/utils/ReentrancyGuardTransient.sol` (last updated
  v5.5.0), and `contracts/access/Ownable.sol` (last updated v5.0.0).
- **How to read this note:** Part A describes what the OpenZeppelin code
  does, from the source. Part B compares it against the from-scratch
  versions in
  [smart-contract-vulnerabilities](https://github.com/imsaylor/smart-contract-vulnerabilities)
  and records what I got right, what differs, and what to study next.
  I have no audit experience behind this note.

## Part A — What the OpenZeppelin code does

### A.1 `ReentrancyGuard` (storage-based, v5.5.0)

The guard is a two-state flag, `NOT_ENTERED = 1` / `ENTERED = 2`, but it
does not live in an ordinary state variable. It lives in a namespaced
storage slot derived from
`keccak256("openzeppelin.storage.ReentrancyGuard")`, accessed through
the `StorageSlot` library (the ERC-7201 namespaced-storage pattern).
That placement is deliberate: in upgradeable/proxy layouts, a plain
state variable can collide with the storage layout of another contract
in the inheritance chain; a namespaced slot cannot.

Three details worth recording:

- The values are non-zero on purpose. The comments explain the
  gas-refund reasoning: storing a non-zero value over a non-zero value
  keeps refunds low, and since refunds are capped at a percentage of
  the transaction's gas, low refunds are more likely to be paid in
  full. Booleans are avoided because the compiler emits an extra SLOAD
  to preserve neighboring bits.
- There is a second modifier, `nonReentrantView`, for view functions:
  it reverts if a guarded function is already on the call stack, but
  does not change the flag, so it cannot be used on state-changing
  functions. Its purpose is to stop reads of inconsistent intermediate
  state during a reentrant call.
- The header marks the storage-based guard **deprecated**: it will be
  removed and replaced by the transient-storage variant in v6.0.

The single-guard limitation is documented in the code: two
`nonReentrant` functions cannot call each other. The recommended
workaround is to make the shared logic `private` and expose separate
`external` `nonReentrant` entry points.

### A.2 `ReentrancyGuardTransient` (v5.1+, updated v5.5.0)

Same shape, same storage-slot constant, but the flag lives in
**transient storage** (EIP-1153, `tload`/`tstore` via the
`TransientSlot` library) as a boolean. Consequences:

- No constructor initialization: transient storage starts cleared in
  every transaction, so there is no `NOT_ENTERED` value to set at
  deployment.
- No persistent SSTORE/SLOAD cost or refund accounting: the flag
  exists only for the transaction.
- It only works on networks where EIP-1153 is available (Cancun and
  later). That availability check is a deployment consideration, not a
  code one.

This is the variant OpenZeppelin is standardizing on, which is why the
storage-based guard is deprecated.

### A.3 `Ownable` (v5.0.0)

A single-owner access control module with four design choices worth
noting:

- The constructor takes an explicit `initialOwner` address instead of
  assuming `msg.sender`. The deployer and the owner are often
  different accounts (factory deployments, multisig owners), and the
  zero address is rejected up front.
- Access checks go through `_msgSender()` from `Context`, not
  `msg.sender` directly, so the module keeps working with
  meta-transaction forwarders that override `_msgSender`.
- Errors carry the offending address: `OwnableUnauthorizedAccount(account)`
  and `OwnableInvalidOwner(owner)`. A revert reason that names the
  account is much easier to debug from a failed transaction than a bare
  revert.
- `renounceOwnership()` exists and is documented as a footgun: it
  leaves the contract permanently ownerless, disabling every
  `onlyOwner` function. `transferOwnership` and the internal
  `_transferOwnership` are `virtual`, and the `OwnershipTransferred`
  event indexes both addresses.

## Part B — Comparison with my lab versions

My lab guard (`ReentrancyGuard.sol`, written from scratch, no
dependencies) and my lab owner pattern (`OwnedTreasury.sol`) were built
before I read these files. The comparison:

| Aspect | My lab version | OpenZeppelin | Verdict |
| --- | --- | --- | --- |
| Guard values 1/2, non-zero | Yes, with the same gas reasoning in comments | Yes, documented the same way | Got it right |
| Guard storage placement | Plain `_status` variable (slot 0) | ERC-7201 namespaced slot via `StorageSlot` | OZ is upgrade-safe; mine is not |
| View-function guard | None | `nonReentrantView` | Gap: I did not know this existed |
| Transient-storage variant | None | `ReentrancyGuardTransient`, the v6 direction | Gap: next thing to study |
| Owner set at deployment | `msg.sender` in constructor | Explicit `initialOwner` argument | OZ handles deployer ≠ owner |
| Sender check | `msg.sender` directly | `_msgSender()` via `Context` | OZ is meta-transaction ready |
| Errors | `NotOwner(caller)`, `ZeroAddress()` | `OwnableUnauthorizedAccount(account)`, `OwnableInvalidOwner(owner)` | Same idea; OZ names the contract in the error |
| Ownership transfer | Zero-address check + indexed event | Same, plus `virtual` internals and `renounceOwnership` | Equivalent for the lab's purpose |

What I would change if I rewrote the lab versions today:

1. Put the guard flag in a namespaced slot and say why, instead of a
   plain variable.
2. Add the transient-storage variant as a second module, with a note
   on which networks support it, and a test showing the same attack
   failing against it.
3. Take the initial owner as a constructor argument.
4. Keep the lab versions dependency-free (that constraint was
   deliberate, so the mechanism stays readable), but state in the
   README that production code should use the reviewed implementations
   — which the README already says.

What to study next, in order: `TransientSlot` and EIP-1153 mechanics;
ERC-7201 namespaced storage; `Context` and `_msgSender`; role-based
access control (`AccessControl.sol`) as the step beyond single-owner.

## Sources

- OpenZeppelin Contracts, `contracts/utils/ReentrancyGuard.sol` at
  commit `7df9390d`.
  https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7df9390d5989ea2cb7a70ad93f96245d8a82574e/contracts/utils/ReentrancyGuard.sol
- OpenZeppelin Contracts, `contracts/utils/ReentrancyGuardTransient.sol`
  at commit `7df9390d`.
  https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7df9390d5989ea2cb7a70ad93f96245d8a82574e/contracts/utils/ReentrancyGuardTransient.sol
- OpenZeppelin Contracts, `contracts/access/Ownable.sol` at commit
  `7df9390d`.
  https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7df9390d5989ea2cb7a70ad93f96245d8a82574e/contracts/access/Ownable.sol
- EIP-1153: Transient storage opcodes.
  https://eips.ethereum.org/EIPS/eip-1153
- EIP-7201: Namespaced storage layout.
  https://eips.ethereum.org/EIPS/eip-7201
