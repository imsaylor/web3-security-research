# Reentrancy

- **Status:** study note, first draft — 2026-11-16
- **Classification:** SWC-107 (Reentrancy); CWE-841 (Improper Enforcement
  of Behavioral Workflow)
- **How to read this note:** Part A summarizes public sources, with a
  citation for every factual claim. Part B is my own analysis and is
  labeled as such. I have no audit experience behind this note; it is
  built from the documents listed in Sources.

## Part A — Summary of public sources

### A.1 What reentrancy is

The Smart Contract Weakness Classification (SWC) registry defines the
attack as follows: "In the reentrancy attack (a.k.a. recursive call
attack), a malicious contract calls back into the calling contract before
the first invocation of the function is finished. This may cause the
different invocations of the function to interact in undesirable ways."
[1]

The Solidity documentation states the underlying mechanism: any
interaction from a contract (A) with another contract (B), and any
transfer of Ether, hands over control to that contract (B), which makes
it possible for B to call back into A before the interaction is
completed. [2]

Two qualifications from the same documentation matter for how broadly
this applies:

- Reentrancy is "not only an effect of Ether transfer but of any function
  call on another contract." [2]
- Multi-contract situations must be taken into account: "A called contract
  could modify the state of another contract you depend on." [2]

### A.2 The mechanics, step by step

The SWC registry illustrates the pattern with a simplified DAO-style
contract whose `withdraw` sends Ether via a low-level call and only
afterward reduces the caller's recorded credit. [1] The Solidity
documentation shows the same ordering bug in a `Fund` contract: the
withdrawal sends the caller's share with `call` and sets the share to
zero only after the call returns. [2]

The sequence, as described across these sources, is:

1. The victim contract checks the caller's recorded balance.
2. It sends Ether (or calls an external contract) **before** updating
   that balance.
3. The recipient is a contract. Receiving the Ether (or the call) executes
   the recipient's code — its `receive`/`fallback` function or a callback —
   while the victim's first call is still on the stack.
4. The recipient's code calls the victim's withdrawal function again.
   Because the balance has not been updated yet, the check in step 1
   passes a second time, and a second payout is issued.
5. The nesting repeats until the victim's balance is drained or the
   transaction runs out of gas. Only then do the stacked calls unwind and
   the balance updates execute — too late. [1][2]

The ConsenSys Diligence best-practices guide adds a warning that applies
even when the called contract is not itself malicious: "malicious code
can be executed by any contracts *it* calls," so every external call
should be treated as a potential security risk. [3]

### A.3 History: The DAO, June–July 2016

The facts in this section come from the U.S. Securities and Exchange
Commission's Report of Investigation into The DAO (Release No. 81207,
July 25, 2017), unless noted otherwise. [4]

- The DAO was created by Slock.it UG and its co-founders as a
  for-profit entity that would pool assets through the sale of DAO Tokens
  and fund "projects," with token holders sharing in anticipated
  earnings. [4]
- From April 30 through May 28, 2016, The DAO sold approximately 1.15
  billion DAO Tokens for approximately 12 million ETH, valued at
  approximately $150 million when the offering closed. [4]
- In late May 2016, concerns about the safety of The DAO's funds began to
  surface. On May 26, 2016, Slock.it submitted a "DAO Security Proposal"
  calling for code updates and the appointment of a security expert; on
  June 3, 2016, Christoph Jentzsch proposed a moratorium on all proposals
  until fixes were implemented. [4]
- On June 17, 2016, an unknown individual or group "began rapidly
  diverting ETH from The DAO, causing approximately 3.6 million ETH — 1/3
  of the total ETH raised by The DAO offering — to move from The DAO's
  Ethereum Blockchain address to an Ethereum Blockchain address
  controlled by the Attacker." [4]
- The diverted ETH could not be moved onward for 27 days, because The
  DAO's code prevented it. [4]
- On July 20, 2016, after a majority of the network adopted updated
  client software, a hard fork became active, transferring all funds
  raised — including those held by the attacker — to a recovery address
  where DAO Token holders could exchange tokens for ETH. A minority
  declined the fork and continued the unaltered chain, now known as
  Ethereum Classic. [4]
- The Commission determined that DAO Tokens were securities, and
  determined not to pursue an enforcement action. [4]

The SEC report describes the event in general terms — "an attacker used a
flaw in The DAO's code to steal approximately one-third of The DAO's
assets." [4] The mechanism behind the theft is documented by technical
reconstructions: The DAO's `split` function, which let token holders exit
into a child DAO, sent ETH to the caller **before** updating the caller's
recorded balance, so a contract that called back into `split` from its
receiving code could withdraw against the same balance repeatedly. [5]
The same reconstruction notes that the 27-day holding period existed
because splits moved ETH into a child DAO subject to its own waiting
period — the feature that gave the community time to organize the fork.
[5] It also notes that the record does not establish that the specific
reentrancy path had been publicly identified with enough precision to
fix before June 17; what was documented before the attack was general
security concern and a proposed moratorium, not a specific unaddressed
disclosure. [5]

### A.4 Detection: what to look for

Drawn from the sources above, the review pattern is:

1. **Find every external call.** Any `.call`, token transfer, or call to
   another contract hands over control flow. [2][3]
2. **Check the ordering.** If any state write — balances, allowances,
   flags, share accounting — happens *after* an external call in the same
   function, the ordering is suspect. The SWC registry's recommended
   practice is that "all internal state changes are performed before the
   call is executed." [1]
3. **Check the guards.** The SWC registry's second recommended practice is
   a reentrancy lock, naming OpenZeppelin's `ReentrancyGuard`. [1]
4. **Do not trust the gas stipend.** `.transfer()` and `.send()` forward
   exactly 2,300 gas, a limit originally intended to prevent reentrancy.
   The ConsenSys guide recommends against relying on it: EIP-1884, in the
   Istanbul hard fork, raised the gas cost of `SLOAD`, which can push a
   recipient's fallback function above 2,300 gas. The guide recommends
   `.call()` instead — while noting explicitly that `.call()` "does
   nothing to mitigate reentrancy attacks," so ordering and guards must
   still be applied. [3]
5. **Check callbacks and hooks, not just Ether transfers.** Token
   standards with receiver hooks (for example ERC-777's `tokensReceived`)
   create the same control-flow handoff. This follows directly from the
   Solidity documentation's statement that reentrancy is an effect of any
   function call on another contract, not only of Ether transfer. [2]

### A.5 Fixes

The fixes below are those prescribed by the sources, not my inventions:

1. **Checks-Effects-Interactions (CEI).** The Solidity documentation
   defines the pattern: complete all checks of the supplied parameters
   first; then make all state changes; only then call functions in other
   contracts. It calls this "a common foolproof way to prevent reentrancy
   attacks." [2] The SWC registry prescribes the same ordering. [1]
2. **Reentrancy guard.** A mutex that reverts on nested entry, such as
   OpenZeppelin's `ReentrancyGuard` with its `nonReentrant` modifier. [1]
3. **Pull over push.** The ConsenSys guide recommends isolating each
   external call into its own transaction initiated by the recipient —
   letting users withdraw funds rather than pushing funds to them
   automatically — which limits the damage when a call fails or is
   abused. [3]
4. **Mark untrusted interactions.** The ConsenSys guide recommends naming
   variables, methods, and interfaces so it is clear that interacting
   with them is potentially unsafe. [3]

## Part B — My analysis

*Everything in this section is my own reasoning, built on the sources
above. It is not quoted from, or endorsed by, any of them.*

### B.1 Why an ordering bug keeps reappearing

Reentrancy survives as a bug class because the vulnerable code reads
correctly in a sequential mental model. `withdraw` looks like three
sensible steps — check the balance, send the money, record the payment —
and in a single-threaded program with no callbacks, that order is fine.
The EVM breaks the model: step two runs arbitrary code belonging to the
recipient, and that code can re-enter step one. The fix is not more
cleverness; it is refusing to hand over control while your own books are
still open. That is why the CEI pattern is stated as an ordering rule
rather than a cleverness rule, and why I treat "state write after an
external call" as the first thing to search for in any review, before
reading the business logic.

### B.2 The DAO's 27 days are the most instructive detail

The theft itself gets the attention, but the response window is the part
worth studying. The same split mechanism that enabled the drain also
locked the proceeds for 27 days, which is the only reason a coordinated
response was possible at all. The lesson I take from this is about
blast radius over time: a withdrawal delay, a timelock, or a
commit-and-reveal step does not fix an ordering bug, but it converts an
instant, irreversible loss into a recoverable incident. When I review
code, I now ask two separate questions: "can this be exploited?" and
"if it is exploited, how much time do we have?" The DAO answers the
second question unusually well, by accident.

### B.3 Guards are a backstop, not the fix

A reentrancy guard and the CEI pattern are often presented as
alternatives. I read them as different layers: CEI removes the
vulnerability by making re-entry harmless (the balance is already
updated when control leaves), while a guard makes re-entry impossible.
The guard protects against the cases where CEI is hard to apply —
cross-function reentrancy, where one function updates shared state that
another function reads, or complex multi-call flows. My working rule:
apply CEI everywhere it fits, add a guard on functions that move value,
and never treat the guard as a reason to skip the ordering.

### B.4 Open questions I still need to answer

- Read-only reentrancy: view functions that read intermediate state
  during a callback and feed it to another protocol. I have not yet read
  a primary write-up of a real incident in this sub-class; it stays on
  the reading list rather than being asserted here.
- How modern static analyzers (Slither, Aderyn) report each reentrancy
  variant, and where their detectors produce false positives. Tool
  practice is scheduled in the curriculum, not claimed here.

## Sources

1. Smart Contract Weakness Classification Registry, SWC-107: Reentrancy.
   https://swcregistry.io/docs/SWC-107
2. Solidity documentation (v0.8.37), Security Considerations.
   https://docs.soliditylang.org/en/v0.8.37/security-considerations.html
3. ConsenSys Diligence, Ethereum Smart Contract Best Practices:
   External Calls.
   https://consensysdiligence.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/
4. U.S. Securities and Exchange Commission, Report of Investigation
   Pursuant to Section 21(a) of the Securities Exchange Act of 1934:
   The DAO, Release No. 81207, July 25, 2017. Text consulted via the
   Internet Archive copy of the release:
   http://ia802805.us.archive.org/6/items/5628492-34-81207/5628492-34-81207_djvu.txt
5. Swoopr Investment, "The DAO Hack and the Ethereum Fork" — case study
   reconstructing the episode from the SEC report and FRED price data.
   https://www.getswoopr.com/market-history/dao-hack-ethereum-fork/

All sources accessed and read on 2026-11-16.
