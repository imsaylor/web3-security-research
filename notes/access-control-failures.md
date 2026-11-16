# Access-Control Failures

- **Status:** study note, first draft — 2026-11-16
- **Classification:** SWC-105 (Unprotected Ether Withdrawal), SWC-106
  (Unprotected SELFDESTRUCT), SWC-112 (Delegatecall to Untrusted Callee),
  SWC-115 (Authorization through tx.origin); CWE-284 (Improper Access
  Control)
- **How to read this note:** Part A summarizes public sources, with a
  citation for every factual claim. Part B is my own analysis and is
  labeled as such. I have no audit experience behind this note; it is
  built from the documents listed in Sources.

## Part A — Summary of public sources

### A.1 What access control is

OpenZeppelin's documentation defines it plainly: access control is "who
is allowed to do this thing," and it "may govern who can mint tokens,
vote on proposals, freeze transfers, and many other things." [1] The
same guide describes the two standard implementations:

- **Ownership** (`Ownable`): a single `owner` account can perform
  administrative tasks. The owner is by default the deploying account,
  can transfer ownership, and can renounce it — with the warning that
  renouncing means `onlyOwner` tasks "will no longer be callable." [1]
- **Role-based access control** (`AccessControl`): multiple roles, each
  allowed to perform different sets of actions, checked with `onlyRole`.
  Roles are identified by `bytes32` constants, granted and revoked
  dynamically, and each role has an admin role that governs granting and
  revocation. [1]

Three warnings from the same guide are worth recording verbatim in
spirit:

- `DEFAULT_ADMIN_ROLE` is the default admin for all roles and is its own
  admin, so it "carries significant risk." OpenZeppelin recommends
  `AccessControlDefaultAdminRules`, which restricts the admin to a single
  account with a two-step transfer procedure and a delay. [1]
- Limiting what each component can do is the principle of least
  privilege, "a good security practice." [1]
- `Ownable` and `AccessControl` "do not address the issue of a
  misbehaving administrator attacking their own system"; that is what
  `TimelockController` addresses, by subjecting maintenance operations
  to a delay so users can review them and exit. [1]

### A.2 The failure patterns, as classified

**Unprotected withdrawal (SWC-105).** "Due to missing or insufficient
access controls, malicious parties can withdraw some or all Ether from
the contract account." The registry notes this bug "is sometimes caused
by unintentionally exposing initialization functions" and prescribes:
"Implement controls so withdrawals can only be triggered by authorized
parties or according to the specs of the smart contract system." [2]

The registry's samples show the pattern at three levels of subtlety
[2]:

- *Trivial:* a `withdrawAllAnyone()` function with no check at all.
- *One missing modifier:* a `MultiOwnable` variant where `newOwner`
  lacks the `onlyOwner` modifier present on every other administrative
  function, so anyone can add themselves as an owner and then call the
  guarded `withdrawAll`.
- *Misnamed constructor:* the Rubixi contract (Solidity 0.4.22), where
  the contract was renamed from `DynamicPyramid` to `Rubixi` but the
  initialization function kept the old name `DynamicPyramid()`. Because
  constructors were then declared as functions sharing the contract's
  name, the renamed contract had no constructor at all — and
  `DynamicPyramid()` became an ordinary public function anyone could
  call to set themselves as `creator`, gaining the `onlyowner` powers.
  [2] In current Solidity, constructors use the `constructor` keyword,
  as shown throughout the current Solidity documentation. [3]

**Authorization through `tx.origin` (SWC-115).** The Solidity
documentation is absolute: "Never use `tx.origin` for authorization."
It demonstrates a wallet whose `transferTo` checks `tx.origin == owner`,
then shows an attack wallet whose `receive` function calls
`transferTo` when the owner sends it Ether: the check sees the owner's
address (the originator of the whole transaction) rather than the
attack wallet's address, and the wallet is drained. The fix is to check
`msg.sender`. [3]

**Delegatecall to untrusted code (SWC-112).** The ConsenSys Diligence
guide warns that `delegatecall` "is used to call functions from other
contracts as if they belong to the caller contract," so "the callee may
change the state of the calling address," and demonstrates a `Worker`
contract that self-destructs when given a `Destructor` address. Its
rule: "Delegate execution only to trusted contracts, and **never to a
user supplied address**." [4] The Solidity documentation adds a related
warning for proxies: if a contract can call arbitrary contracts with
user-supplied data, "the user can essentially assume the identity of
the proxy contract," and the proxy should hold no permissions of its
own. [3]

### A.3 Case study: the Parity multisig incidents, 2017

Both incidents hit the same codebase and the same function. They are
the clearest public demonstration that an initialization bug is an
access-control bug.

**Incident 1 — July 19, 2017: ownership takeover and theft.**

OpenZeppelin's analysis, published the same day, reports that as of
12:19 UTC the attacker's account had drained 153,037 ETH from three
multi-signature contracts used to store funds from past token sales,
and that the vulnerability affected Parity Multisig Wallet version
1.5+. [5]

The mechanism, per the same analysis [5]:

- The wallet contract forwarded all unmatched function calls to a shared
  library contract using `delegatecall`.
- This made "all public functions from the library callable by anyone,"
  including `initWallet`, which sets the contract's owners.
- `initWallet` had "no checks to prevent an attacker from calling it
  after the contract was initialized."
- The attacker sent two transactions to each affected contract: the
  first called `initWallet` to replace the owner list with only the
  attacker's address and require just one confirmation; the second
  invoked `execute` to move all funds, automatically authorized because
  the attacker was now the sole owner.

OpenZeppelin's stated fix: the attack "could have been prevented either
by not extracting the constructor logic into the library contract
altogether, or better by *not using `delegatecall` as a catch-all
forwarding mechanism*," recommending instead that the wallet explicitly
define which library functions can be invoked externally. [5]

**Incident 2 — November 6, 2017: library destruction and freeze.**

After the July incident, Parity deployed a new version of the wallet
library contract on July 20, 2017. The replacement code contained a
related issue: the library contract itself had never been initialized,
so anyone could call `initWallet` on the library directly and become
its owner. [6][7]

The sequence, as reported [6][7]:

- On November 6, 2017, a user known as `devops199` called `initWallet`
  on the library contract, becoming its owner, and then called its
  `kill` function, which executed `selfdestruct` and deleted the
  library's code. Whether this was done purposefully "has not been
  established." [6]
- Because every affected wallet delegated its logic to that single
  library, all of them became unusable: their funds could not be moved.
  Nothing was stolen; the funds became unreachable. [6][7]
- The issue affected only wallets created on or after July 20, 2017,
  because they used the new code. [6]
- The scale: Parity's postmortem put the frozen funds at 513,774.16 ETH
  across 587 wallets, as reported by Computing. [6] CoinDesk, reporting
  the same postmortem, described "more than 500 affected wallets" and
  cited 584 wallets per Parity's tracker website, with roughly $160
  million worth of ether frozen and no immediate solution. [7] The two
  wallet counts differ between the reports; both are recorded here
  rather than reconciled.

Two facts from Parity's own postmortem, as quoted in the reporting,
deserve emphasis [6]:

- The risk had been flagged in August 2017. A GitHub contributor,
  `3esmit`, had recommended that `initWallet` be called at deployment;
  Parity treated the recommendation as a "convenience enhancement" to be
  deployed "in a regular update at a future point in time," and the fix
  was not in place when the library was destroyed.
- Parity identified two ways the exploit could have been avoided: "If
  the contract code had not included the functionality to suicide or
  kill, even if someone had taken ownership, they would not have been
  able to do anything. The kill functionality was a remainder of the
  original audited contract." The other was initializing the library as
  `3esmit` had proposed. [6]

Following the incident, Parity removed the ability to deploy multi-sig
wallets "until we feel we have the correct security and operations
procedures in place," and said it would work on Ethereum improvement
proposals that might restore access. [7]

### A.4 Detection: what to look for

Drawn from the sources above:

1. **Enumerate every privileged function** — mint, burn, withdraw,
   sweep, pause, upgrade, ownership transfer, fee and oracle
   configuration — and verify each has a check. The SWC-105 samples show
   the failure is usually one function, not the whole contract. [2]
2. **Trace every initialization path.** Initialization functions are
   the recurring weak point in this note's sources: Parity's
   `initWallet` twice, Rubixi's misnamed constructor. Ask: can this be
   called twice? Can it be called on the implementation contract
   itself, not just through a proxy? Can it be called by anyone? [2][5][6]
3. **Check `selfdestruct` and `delegatecall` together.** An unguarded
   `selfdestruct` in shared code turns an ownership bug into a
   destruction bug; a catch-all `delegatecall` turns a library's public
   functions into the caller's public functions. [4][5][6]
4. **Search for `tx.origin` in authorization checks.** Any occurrence is
   a finding on its own. [3]
5. **Test from an unprivileged account.** The practical check for every
   item above: call each privileged function from an address that holds
   no role and confirm it reverts. This is the test form of the
   "authorized parties" prescription in SWC-105. [2]

## Part B — My analysis

*Everything in this section is my own reasoning, built on the sources
above. It is not quoted from, or endorsed by, any of them.*

### B.1 Initialization is where access control is most often absent

Three of the four failure stories in this note — both Parity incidents
and Rubixi — are initialization failures, not failures of a permission
check on a normal function. The pattern is consistent: setup code is
written as if it runs once, at deployment, in a trusted context, and
then it turns out to be callable later, by anyone, in an untrusted
context. My working rule is to treat every initializer as a privileged
function first and a setup convenience second: it needs the same
scrutiny as `withdraw`, plus the extra questions of re-invocation and
of who can call it on each deployed instance, including the logic
contract behind a proxy.

### B.2 Shared code means shared fate

Parity's library pattern meant one contract's compromise was every
wallet's compromise — first as theft (through each wallet's
`delegatecall`), then as a freeze (through the library's destruction).
The efficiency argument for shared logic is real: one deployment, lower
gas, consistent behavior. But the failure mode scales with the sharing.
When I review proxy or library patterns, I now ask: "if this shared
contract is taken over or destroyed, what is the full list of contracts
that stop working or become drainable?" If the answer is "all of them,"
the shared contract's initialization and self-destruction paths deserve
the same attention as the money-moving functions.

### B.3 Leftover functionality is a liability, not dead code

Parity's own postmortem calls the `kill` function "a remainder of the
original audited contract." It survived a refactor that changed
everything around it, and it was the function that converted an
ownership bug into a permanent freeze. The general form of this lesson:
a function that exists but is never meant to be called in production is
not harmless; it is an untested, unreviewed entry point. When I see
`selfdestruct`, `suicide`, or an emergency function in a review, my
first question is whether it needs to exist at all, and my second is
who can call it — in that order.

### B.4 The August warning is a process finding, not a code finding

`3esmit`'s recommendation was received, understood well enough to be
implemented in code, and then scheduled as a future enhancement while
the vulnerable library stayed live. The code fix existed; the deployment
decision did not treat it as urgent. I record this because it changes
how I think about severity: a known uninitialized implementation
contract with a written fix that has not shipped is not a low-priority
cleanup item. In a review, I would treat "known but unscheduled" as part
of the finding, not as a mitigating factor.

### B.5 Open questions I still need to answer

- How OpenZeppelin's upgradeable-contracts pattern (`initializer`
  modifiers, `_disableInitializers` in the implementation constructor)
  addresses each failure in this note, read from the actual
  implementation rather than from summaries.
- The post-Cancun behavior of `SELFDESTRUCT` under EIP-6780, and
  precisely which parts of the November 2017 scenario it does and does
  not prevent. I have seen the claim that it "neuters" the pattern; I
  have not yet read the EIP itself, so it is not asserted here.

## Sources

1. OpenZeppelin documentation (Contracts 4.x), Access Control.
   https://docs.openzeppelin.com/contracts/4.x/access-control
2. Smart Contract Weakness Classification Registry, SWC-105:
   Unprotected Ether Withdrawal.
   https://swcregistry.io/docs/SWC-105/
3. Solidity documentation (v0.8.37), Security Considerations.
   https://docs.soliditylang.org/en/v0.8.37/security-considerations.html
4. ConsenSys Diligence, Ethereum Smart Contract Best Practices:
   External Calls (section: "Don't delegatecall to untrusted code").
   https://consensysdiligence.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/
5. OpenZeppelin blog (Santiago Palladino), "The Parity Wallet Hack
   Explained," July 19, 2017.
   https://www.openzeppelin.com/news/on-the-parity-wallet-multisig-hack-405a8c12e8f7
6. Computing, "Parity knew about wallet bug in August — still no fix
   for frozen funds," November 20, 2017 (reporting Parity's postmortem
   and quoting it).
   https://www.computing.co.uk/news/3021517/parity-knew-about-wallet-bug-in-august-still-no-fix-for-frozen-funds
7. CoinDesk, "Parity Team Publishes Postmortem on $160 Million Ether
   Freeze," November 15, 2017.
   https://www.coindesk.com/markets/2017/11/15/parity-team-publishes-postmortem-on-160-million-ether-freeze

All sources accessed and read on 2026-11-16.
