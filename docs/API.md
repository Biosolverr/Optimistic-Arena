# API (OptimisticArena)

## Write
- create_session(...)
- join_session(session_id)
- start_round(session_id, prompt="")
- submit(session_id, text)
- submit_with_llm(session_id)
- close_submissions(session_id)
- vote(session_id, candidate_hex)
- finalize_round(session_id)

### AI-score appeals
- appeal_ai_score(session_id, round_no)

### Optimistic claim
- optimistic_claim_winner(session_id, candidate_hex, reason="")
- optimistic_claim_by_votes(session_id)
- optimistic_claim_by_llm(session_id)
- challenge_claim(session_id, alternative_hex, reason)
- finalize_claim(session_id)

### XP
- reward_player(session_id, round_no, player_hex, amount)
- add_xp(player_hex, amount)

## View
- get_session(session_id)
- get_round_info(session_id, round_no)
- list_round_submissions(session_id, round_no)
- get_xp(player_hex), get_my_xp(), get_wins(player_hex)
