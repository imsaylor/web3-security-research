# Web3 Security Research

Study notes on smart contract security, written from primary sources and
kept honest about what they are: reading notes, not audit reports.

## Ground rules for this repository

1. **Every factual claim carries a citation.** Sources are listed at the end
   of each note with URLs, and claims in the text point to them.
2. **Summary and analysis are kept apart.** Each note has a Part A that
   summarizes public sources and a Part B that is my own analysis. The two
   are never mixed without a label.
3. **No invented experience.** Nothing here implies audit work, client work,
   or findings I do not have. Where a note draws on my own reasoning, it
   says so.
4. **Code samples are illustrations, not production code.** Vulnerable
   samples are marked as such. Nothing here is meant to be deployed.

## Notes

| Note | Subject | Status |
| ---- | ------- | ------ |
| [notes/reentrancy.md](notes/reentrancy.md) | Reentrancy: mechanism, The DAO, detection, fixes (SWC-107) | First draft, 2026-11-16 |
| [notes/access-control-failures.md](notes/access-control-failures.md) | Access-control failures: Parity multisig incidents, initialization bugs, `tx.origin`, unprotected withdrawal (SWC-105, SWC-106, SWC-112, SWC-115) | First draft, 2026-11-16 |

## Sources consulted so far

- U.S. Securities and Exchange Commission, *Report of Investigation Pursuant
  to Section 21(a) of the Securities Exchange Act of 1934: The DAO*,
  Release No. 81207, July 25, 2017.
- Solidity documentation, *Security Considerations* (v0.8.37).
- Smart Contract Weakness Classification Registry: SWC-105, SWC-107.
- ConsenSys Diligence, *Ethereum Smart Contract Best Practices*
  (External Calls).
- OpenZeppelin blog, *The Parity Wallet Hack Explained* (July 19, 2017);
  OpenZeppelin documentation, *Access Control*.
- Harvest Finance, *Harvest Flashloan Economic Attack Post-Mortem*
  (October 26, 2020) — cited in the DeFi companion repository.
- Uniswap, *Uniswap v2 Core* whitepaper (Adams, Zinsmeister, Robinson,
  March 2020) — cited in the DeFi companion repository.

Full URLs live in each note's Sources section.

## What this repository is not

- It is not a collection of audit findings. Verified findings, if any ever
  exist, belong in the `bug-bounty-reports` repository.
- It is not a tutorial for attacking live systems. The incidents studied
  here are public history; the exercises are local-only.
