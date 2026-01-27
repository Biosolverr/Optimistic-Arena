# # OptimisticArena (GenLayer Intelligent Contract)

On-chain writing arena with:
- sessions + rounds
- optional LLM prompts / LLM submissions
- LLM moderation + scoring (clarity/creativity/relevance)
- human voting
- deterministic finalize (60% votes / 40% AI)
- optimistic claim → challenge → finalize-claim
- AI-score appeals with XP bond

## Repo
- `contracts/optimistic_arena.py` — contract
- `docs/API.md` — public methods
- `docs/ARCHITECTURE.md` — phase flow + resolution modesOptimistic-Arena
