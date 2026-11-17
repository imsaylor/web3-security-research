# Transient Storage and the Reentrancy Guard

- **Status:** study note + lab — 2026-11-17
- **What I read:** the actual source files in
  `OpenZeppelin/openzeppelin-contracts` at commit
  `7df9390d5989ea2cb7a70ad93f96245d8a82574e` (same commit as the chunk-1
  note): `contracts/utils/TransientSlot.sol` (last updated v5.3.0) and
  `contracts/utils/ReentrancyGuardTransient.sol` (last updated v5.5.0).
- **What I built and tested:** `ReentrancyGuardTransient.sol` and
  `TransientVault.sol` in
  [smart-contract-vulnerabilities](https://github.com/imsaylor/smart-contract-vulnerabilities),
  plus `test/TransientGuard.t.sol` — 4 new tests, all passing with
  `forge test` (Foundry 1.9.0, Solidity 0.8.24). I have no audit
  experience behind this note.

## Part A — What transient storage is

EIP-1153 adds two opcodes, `TSTORE` and `TLOAD`, and a key-value store
that behaves like storage during a transaction and is wiped when the
transaction ends. A value written in one transaction is never visible in
the next. Each `TSTORE`/`TLOAD` costs 100 gas, against thousands for
`SSTORE`/`SLOAD` on a cold slot, which is why the textbook use case is a
reentrancy lock: the flag only needs to live for one call frame anyway.

Two consequences follow from the one-transaction lifetime, and both matter
for how the guard is written:

- **No initialisation.** A storage guard needs a constructor that sets
  the flag to "not entered", because persistent storage starts at zero and
  zero is ambiguous. A transient flag starts cleared in every transaction,
  so there is nothing to initialise at deployment.
- **The flag must still be cleared at the end of the guarded function.**
  The wipe at transaction end makes that write redundant for the *next*
  transaction, but not for a second call in the *same* transaction — two
  withdrawals inside one multicall, for example. OpenZeppelin's guard
  writes `false` at the end for exactly this reason, and the lab guard
  does the same.

## Part B — How OpenZeppelin uses it

### B.1 `ReentrancyGuardTransient`

Same shape as the storage guard — a `nonReentrant` modifier that reverts
on re-entry, plus a `nonReentrantView` variant for view functions — but the
flag is a boolean at a namespaced slot, read and written through the
`TransientSlot` library. The slot constant is the ERC-7201 slot derived
from `"openzeppelin.storage.ReentrancyGuard"`:

```solidity
// keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
bytes32 private constant REENTRANCY_GUARD_STORAGE =
    0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;
```

Note that this is **not** the plain `keccak256` of the string. ERC-7201
takes the hash, subtracts one, hashes again as an encoded uint, and clears
the low byte. I verified the constant above against the source at commit
`7df9390d` rather than trusting memory — my first draft of it had an extra
hex digit, which the compiler caught.

### B.2 `TransientSlot`: two ways to pick a slot

The library offers two forms, and the difference is worth recording
because it is easy to get wrong:

1. **A fixed slot.** `REENTRANCY_GUARD_STORAGE.asBoolean()` wraps the
   constant above; `tload`/`tstore` use it directly. Simple, and the slot
   is the same in every contract that uses the constant.
2. **A reserved slot.** Declare `TransientSlot.TBoolean private _lock;`
   and use `_lock.tload()` / `_lock.tstore(...)`. The struct reserves a
   slot in the *persistent* layout that is never written to; the value is
   held in the transient slot whose number is the **bitwise complement**
   (`not`) of the reserved slot. Reservations therefore grow down from the
   top of the transient space, away from the slots the compiler allocates
   for native `transient` variables (which start at slot 0). Reserving the
   struct inside an ERC-7201 namespaced storage struct namespaces the
   transient slot the same way it namespaces persistent ones.

The library is procedurally generated from a template, and it covers
`address`, `bool`, `bytes32`, `uint256` and `int256`, each in both forms.

### B.3 The compiler-version fact that decided the lab implementation

The `transient` keyword for state variables did **not** arrive with the
opcodes. The version history, checked by compiling:

| Version | What changed |
| ------- | ------------ |
| 0.8.24 (Jan 2024) | `tstore` / `tload` builtins in Yul/inline assembly (Cancun opcodes) |
| 0.8.27 (Sep 2024) | Parser accepts the `transient` keyword, but generates no code yet |
| 0.8.28 (Oct 2024) | `transient` state variables of value types fully supported |

This lab pins Solidity 0.8.24, so the `transient` keyword is not available
here: `bool transient _entered;` fails to parse under 0.8.24 and compiles
under 0.8.30 (both verified locally). The lab guard therefore uses the
assembly form — `tload`/`tstore` at the same ERC-7201 slot OpenZeppelin
uses — instead of the keyword form. The observable behaviour is identical;
the keyword form would only become an option if the repo's compiler pin
moves to 0.8.28 or later. One more restriction from the docs: only value
types can be transient; mappings, arrays and structs cannot.

## Part C — What the lab proves

`TransientVault` is `FixedVault` with exactly one change: the guard flag
lives in transient storage. Everything else — checks-effects-interactions
ordering, errors, interface — is identical, so the tests compare the two
guards directly.

| Test | Result |
| ---- | ------ |
| Same attacker, same setup (2 × 5 ether honest deposits) | Attacker leaves with only its 1 ether seed; victim funds intact |
| Honest withdrawal | Works, ledger zeroed, vault keeps the other deposit |
| Guard reset across transactions | Alice withdraws, deposits again, withdraws again — second withdrawal succeeds (flag did not leak across transactions) |
| Gas: storage-guard withdraw vs transient-guard withdraw | **38,450 vs 33,722 gas — saving 4,728 gas (~12%)** for the same withdrawal |

The full suite is 19 tests, 0 failures (`forge test`, Foundry 1.9.0,
Solidity 0.8.24, Cancun EVM).

## Part D — What I got wrong while building this

Two mistakes, both caught by the tools rather than by review:

1. **The slot constant.** My first draft of the ERC-7201 slot had 65 hex
   digits instead of 64. The compiler rejected it, and the fix was to copy
   the constant verbatim from the OpenZeppelin source rather than from
   memory. Lesson: never hand-copy a magic constant; cite the source file
   and verify the length.
2. **The test setup.** I funded Alice and Bob with 5 ether each, then
   deposited 5 ether into *two* vaults per person — the second deposit
   reverted with `OutOfFunds`. The trace showed it immediately. Lesson:
   when one test funds two contracts, fund each account for both.

A third thing is a deliberate scope choice, not a mistake: the lab guard
has no `nonReentrantView` variant (chunk 1 flagged that as a gap in the
storage guard too). Adding it is a small, well-defined next step.

## Part E — Slither: planned, not yet run

Static analysis is the next module in this curriculum chunk. Slither
(Trail of Bits) is the tool to learn first, because it has a dedicated
reentrancy detector. The plan, for when the tool is installed:

```sh
pip install slither-analyzer
slither src/reentrancy/VulnerableVault.sol --detect reentrancy-eth
slither src/reentrancy/FixedVault.sol --detect reentrancy-eth
slither src/reentrancy/TransientVault.sol --detect reentrancy-eth
```

Expected outcome, to be verified by running it rather than assumed:
`VulnerableVault` flagged by `reentrancy-eth`, both fixed vaults clean.
If Slither flags the transient guard itself (for example because it does
not model `tstore`/`tload`), that is a finding about the tool, not about
the guard — record it either way. Installing Slither needs a decision
first (new tool on the machine), so it is **not** done yet.

## What to study next, in order

ERC-7201 namespaced storage (now that the slot formula is concrete);
`Context` and `_msgSender`; role-based access control
(`AccessControl.sol`) as the step beyond single-owner; then the Slither
run above, and a `nonReentrantView` variant for both lab guards.

## Sources

- OpenZeppelin Contracts, `contracts/utils/ReentrancyGuardTransient.sol`
  at commit `7df9390d`.
  https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7df9390d5989ea2cb7a70ad93f96245d8a82574e/contracts/utils/ReentrancyGuardTransient.sol
- OpenZeppelin Contracts, `contracts/utils/TransientSlot.sol` at commit
  `7df9390d`.
  https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7df9390d5989ea2cb7a70ad93f96245d8a82574e/contracts/utils/TransientSlot.sol
- EIP-1153: Transient storage opcodes.
  https://eips.ethereum.org/EIPS/eip-1153
- EIP-7201: Namespaced storage layout.
  https://eips.ethereum.org/EIPS/eip-7201
- Solidity documentation, layout of state variables in storage and
  transient storage (v0.8.28).
  https://docs.soliditylang.org/en/v0.8.28/internals/layout_in_storage.html
