# Architecture

## Phases
- 0 LOBBY
- 1 SUBMISSIONS
- 2 VOTING

## Deterministic finalize (60/40)
Normalize votes and AI totals to [0..1000], then:
total = votes*60 + ai*40
Tie-break: smallest address hex.

## Optimistic claim
Host can claim winner during VOTING.
Claim locks starting a new round until finalized.
If challenged: LLM judge picks from (claimed + alternatives) or fallback to vote tally.
