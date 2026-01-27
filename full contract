# v0.1.0
# { "Depends": "py-genlayer:latest" }
from genlayer import *
import typing
import time
import json


class OptimisticArena(gl.Contract):
    # -------------------------
    # persisted storage
    # -------------------------
    next_session_id: u256
    last_session_id: u256  # удобный хелпер

    # session meta
    session_host: TreeMap[u256, Address]
    session_max_players: TreeMap[u256, u256]
    session_member_count: TreeMap[u256, u256]
    session_round_no: TreeMap[u256, u256]
    session_phase: TreeMap[u256, u256]  # 0=LOBBY, 1=SUBMISSIONS, 2=VOTING

    # per-session config
    session_challenge_period_sec: TreeMap[u256, u256]  # seconds (окно для challenge claim'а)
    session_llm_prompts_enabled: TreeMap[u256, u256]   # 0/1
    session_llm_judge_enabled: TreeMap[u256, u256]     # 0/1
    session_appeal_bond_xp: TreeMap[u256, u256]        # XP-бонд за appeal AI-оценки
    session_appeal_period_sec: TreeMap[u256, u256]     # окно апелляции AI-оценок

    # lock new rounds while a claim is pending
    session_active_claim_round: TreeMap[u256, u256]    # 0 or round_no

    # members stored as "array via TreeMap"
    session_member_at: TreeMap[str, Address]           # "{sid}:{idx}" -> Address
    session_member_index: TreeMap[str, u256]           # "{sid}:{addr_hex}" -> idx+1

    # round prompt/state
    round_prompt: TreeMap[str, str]                    # "{sid}:{round}" -> prompt

    # submissions
    round_submission: TreeMap[str, str]                # "{sid}:{round}:{addr_hex}" -> text
    round_has_submitted: TreeMap[str, u256]            # 0/1
    round_submission_valid: TreeMap[str, u256]         # 0/1 — прошла ли AI-модерацию

    # AI scores per submission
    round_score_clarity: TreeMap[str, u256]            # 0..10
    round_score_creativity: TreeMap[str, u256]         # 0..10
    round_score_relevance: TreeMap[str, u256]          # 0..10

    # votes
    round_vote_of: TreeMap[str, str]                   # "{sid}:{round}:{voter_hex}" -> candidate_hex
    round_votes_for: TreeMap[str, u256]                # "{sid}:{round}:{candidate_hex}" -> votes

    # scoring / appeals
    round_scored: TreeMap[str, u256]                   # 0/1 — LLM уже проставил оценки
    round_appeal_deadline: TreeMap[str, u256]          # unix seconds для AI-score appeals
    submission_appealed: TreeMap[str, u256]            # "{sid}:{round}:{addr_hex}" -> 0/1 (одна апелляция на ответ)

    # finalization status
    # 0=NOT_FINAL, 1=FINALIZED (детермин. или через claim), 2=CLAIM_PENDING
    round_finalized: TreeMap[str, u256]

    # optimistic claim / dispute (per round "{sid}:{round}")
    round_claimed_winner: TreeMap[str, Address]
    round_claim_reason: TreeMap[str, str]
    round_claim_deadline: TreeMap[str, u256]           # unix seconds
    round_challenge_count: TreeMap[str, u256]          # number of challenges

    # challenges by index: "{sid}:{round}:{i}"
    round_challenge_who: TreeMap[str, Address]
    round_challenge_alt: TreeMap[str, Address]
    round_challenge_reason: TreeMap[str, str]
    # guard: one challenge per challenger: "{sid}:{round}:{challenger_hex}" -> 0/1
    round_challenged_by: TreeMap[str, u256]

    # final result
    round_final_winner: TreeMap[str, Address]
    # mode: 0=unknown, 1=deterministic_finalize(60/40), 2=accepted_claim,
    #       3=llm_override, 4=votes_fallback
    round_resolution_mode: TreeMap[str, u256]
    round_llm_explanation: TreeMap[str, str]

    # season stats
    season_xp: TreeMap[Address, u256]
    season_wins: TreeMap[Address, u256]

    # -------------------------
    # constants / helpers
    # -------------------------
    def _PHASE_LOBBY(self) -> u256: return u256(0)
    def _PHASE_SUBMISSIONS(self) -> u256: return u256(1)
    def _PHASE_VOTING(self) -> u256: return u256(2)

    def _now(self) -> u256:
        # В GenVM clock_time_get отдаёт unix‑timestamp транзакции. ([docs.genlayer.com](https://docs.genlayer.com/understand-genlayer-protocol/core-concepts/non-deterministic-operations-handling))
        return u256(int(time.time()))

    def _sid(self, session_id: int) -> u256:
        if session_id <= 0:
            raise UserError("session_id must be > 0")
        return u256(session_id)

    def _rk(self, sid: u256, rnd: u256) -> str:
        return f"{int(sid)}:{int(rnd)}"

    def _mkey(self, sid: u256, addr: Address) -> str:
        return f"{int(sid)}:{addr.as_hex}"

    def _mkey_idx(self, sid: u256, idx: int) -> str:
        return f"{int(sid)}:{idx}"

    def _skey(self, sid: u256, rnd: u256, addr: Address) -> str:
        return f"{int(sid)}:{int(rnd)}:{addr.as_hex}"

    def _voter_key(self, sid: u256, rnd: u256, voter: Address) -> str:
        return f"{int(sid)}:{int(rnd)}:{voter.as_hex}"

    def _cand_key(self, sid: u256, rnd: u256, cand_hex: str) -> str:
        return f"{int(sid)}:{int(rnd)}:{cand_hex}"

    def _chk_key(self, sid: u256, rnd: u256, idx: int) -> str:
        return f"{int(sid)}:{int(rnd)}:{idx}"

    def _challenged_by_key(self, sid: u256, rnd: u256, who: Address) -> str:
        return f"{int(sid)}:{int(rnd)}:{who.as_hex}"

    def _require_session(self, sid: u256) -> None:
        if self.session_host.get(sid) is None:
            raise UserError("Unknown session")

    def _require_host(self, sid: u256) -> None:
        if gl.message.sender_address != self.session_host[sid]:
            raise UserError("Only host")

    def _is_member(self, sid: u256, addr: Address) -> bool:
        return self.session_member_index.get(self._mkey(sid, addr), u256(0)) != u256(0)

    def _require_member(self, sid: u256, addr: Address) -> None:
        if not self._is_member(sid, addr):
            raise UserError("Only members can do this")

    def _phase(self, sid: u256) -> u256:
        return self.session_phase.get(sid, self._PHASE_LOBBY())

    def _active_claim_round(self, sid: u256) -> u256:
        return self.session_active_claim_round.get(sid, u256(0))

    def _require_no_active_claim(self, sid: u256) -> None:
        if self._active_claim_round(sid) != u256(0):
            raise UserError("Active claim pending; finalize it before starting a new round")

    def _require_round_exists(self, sid: u256) -> u256:
        rnd = self.session_round_no.get(sid, u256(0))
        if rnd == u256(0):
            raise UserError("Round not started")
        return rnd

    def _parse_json(self, raw: str) -> typing.Any:
        cleaned = raw.replace("```json", "").replace("```", "").strip()
        return json.loads(cleaned)

    # -------------------------
    # LLM helpers via gl._nondet (Equivalence Principle)
    # -------------------------
    def _ai_generate_prompt(self, sid: u256, rnd: u256) -> str:
        """
        Генерация промпта раунда (AI game designer).
        """
        member_count = int(self.session_member_count.get(sid, u256(0)))
        base_info = f"{member_count} players" if member_count > 0 else "no players yet"

        task = (
            "You are a game designer for a GenLayer writing arena.\n"
            "Generate ONE short, fun prompt for a 1-sentence creative answer.\n"
            "Context: this is a public on-chain round with " + base_info + ".\n"
            "Requirements:\n"
            "- The prompt MUST be understandable for a beginner.\n"
            "- It MUST mention 'GenLayer' or 'Intelligent Contracts'.\n"
            "- Max length 200 characters.\n"
            "Return STRICT JSON with a single field:\n"
            "{\"prompt\": \"...\"}\n"
            "No markdown, no ``` fences."
        )

        def leader() -> str:
            res = _prompt(task)
            return str(res)

        def validator(result) -> bool:
            try:
                raw = result.value  # type: ignore[attr-defined]
            except Exception:
                return False
            try:
                data = self._parse_json(str(raw))
            except Exception:
                return False
            p = data.get("prompt")
            if not isinstance(p, str):
                return False
            if len(p) == 0 or len(p) > 200:
                return False
            lower = p.lower()
            if ("genlayer" not in lower) and ("intelligent contract" not in lower):
                return False
            return True

        out = gl._nondet(leader, validator)
        data = self._parse_json(str(out))
        return typing.cast(str, data["prompt"])

    def _ai_generate_submission(self, prompt: str) -> str:
        """
        LLM-помощник пишет один короткий ответ.
        """
        task = (
            "You are a witty player in a GenLayer writing game.\n"
            "Write ONE smart, concise line answering the given prompt.\n"
            "Requirements:\n"
            "- Plain text only (no quotes/markdown).\n"
            "- Single line (no newline chars).\n"
            "- Length <= 160 characters.\n"
            "- Non-empty.\n\n"
            f"Prompt: {json.dumps(prompt)}\n\n"
            "Return STRICT JSON: {\"answer\": \"...\"}."
        )

        def leader() -> str:
            res = _prompt(task)
            return str(res)

        def validator(result) -> bool:
            try:
                raw = result.value  # type: ignore[attr-defined]
            except Exception:
                return False
            try:
                data = self._parse_json(str(raw))
            except Exception:
                return False
            ans = data.get("answer")
            if not isinstance(ans, str):
                return False
            if len(ans) == 0 or len(ans) > 160:
                return False
            if "\n" in ans or "\r" in ans:
                return False
            return True

        out = gl._nondet(leader, validator)
        data = self._parse_json(str(out))
        return typing.cast(str, data["answer"])

    def _ai_moderate_and_score(self, prompt: str, answer: str) -> tuple[bool, int, int, int]:
        """
        AI‑модерация + AI‑оценка:
        - ok = True/False (пропустить ли ответ),
        - clarity / creativity / relevance в [0..10].
        """
        task = (
            "You are an AI moderator and judge for a GenLayer party game.\n"
            "For the given prompt and answer, you MUST:\n"
            "1) Decide if the answer is acceptable (not spam, not obviously toxic, on-topic enough).\n"
            "2) Score it on three dimensions from 0 to 10:\n"
            "   - clarity: how clear/understandable is the answer?\n"
            "   - creativity: how original/fun is the answer?\n"
            "   - relevance: how well does it address the prompt?\n\n"
            "Return STRICT JSON:\n"
            '{\"ok\": true/false, \"clarity\": int, \"creativity\": int, \"relevance\": int}\n'
            "Additional rules:\n"
            "- If ok is false, all three scores MUST be 0.\n"
            "- If ok is true, each score MUST be between 0 and 10 inclusive.\n"
            "No markdown, no ``` fences."
        )

        full = {
            "prompt": prompt,
            "answer": answer,
        }

        def leader() -> str:
            res = _prompt(task + "\n\n" + json.dumps(full))
            return str(res)

        def validator(result) -> bool:
            try:
                raw = result.value  # type: ignore[attr-defined]
            except Exception:
                return False
            try:
                data = self._parse_json(str(raw))
            except Exception:
                return False
            ok = data.get("ok")
            c = data.get("clarity")
            cr = data.get("creativity")
            r = data.get("relevance")
            if not isinstance(ok, bool):
                return False
            if not isinstance(c, int) or not isinstance(cr, int) or not isinstance(r, int):
                return False
            if not (0 <= c <= 10 and 0 <= cr <= 10 and 0 <= r <= 10):
                return False
            if ok is False and (c != 0 or cr != 0 or r != 0):
                return False
            return True

        out = gl._nondet(leader, validator)
        data = self._parse_json(str(out))
        ok = bool(data["ok"])
        c = int(data["clarity"])
        cr = int(data["creativity"])
        r = int(data["relevance"])
        return ok, c, cr, r

    def _ai_rescore_submission(self, prompt: str, answer: str) -> tuple[int, int, int]:
        """
        AI‑пересчёт оценок по апелляции (без повторной модерации).
        """
        task = (
            "You are an AI judge reconsidering a previous score for a GenLayer game answer.\n"
            "Re-score the same answer on:\n"
            "- clarity (0..10)\n"
            "- creativity (0..10)\n"
            "- relevance (0..10)\n"
            "Return STRICT JSON: {\"clarity\": int, \"creativity\": int, \"relevance\": int}.\n"
            "No markdown, no ``` fences."
        )

        full = {
            "prompt": prompt,
            "answer": answer,
        }

        def leader() -> str:
            res = _prompt(task + "\n\n" + json.dumps(full))
            return str(res)

        def validator(result) -> bool:
            try:
                raw = result.value  # type: ignore[attr-defined]
            except Exception:
                return False
            try:
                data = self._parse_json(str(raw))
            except Exception:
                return False
            c = data.get("clarity")
            cr = data.get("creativity")
            r = data.get("relevance")
            if not isinstance(c, int) or not isinstance(cr, int) or not isinstance(r, int):
                return False
            if not (0 <= c <= 10 and 0 <= cr <= 10 and 0 <= r <= 10):
                return False
            return True

        out = gl._nondet(leader, validator)
        data = self._parse_json(str(out))
        return int(data["clarity"]), int(data["creativity"]), int(data["relevance"])

    def _ai_pick_winner_from_set(
        self,
        sid: u256,
        rnd: u256,
        allowed_hexes: list[str],
        context_reason: str,
    ) -> tuple[Address, str]:
        """
        LLM выбирает победителя среди ограниченного множества allowed_hexes
        с учётом текстов, голосов и AI‑оценок.
        """
        rk = self._rk(sid, rnd)
        member_count = int(self.session_member_count.get(sid, u256(0)))
        if member_count == 0:
            raise UserError("No members")

        allowed_set = set(allowed_hexes)

        prompt_text = self.round_prompt.get(rk, "")
        cand_lines: list[str] = []

        for i in range(member_count):
            addr = self.session_member_at[self._mkey_idx(sid, i)]
            h = addr.as_hex
            if h not in allowed_set:
                continue
            sk = self._skey(sid, rnd, addr)
            if self.round_has_submitted.get(sk, u256(0)) != u256(1):
                continue
            if self.round_submission_valid.get(sk, u256(0)) != u256(1):
                continue
            sub = self.round_submission.get(sk, "")
            v = int(self.round_votes_for.get(self._cand_key(sid, rnd, h), u256(0)))
            c = int(self.round_score_clarity.get(sk, u256(0)))
            cr = int(self.round_score_creativity.get(sk, u256(0)))
            r = int(self.round_score_relevance.get(sk, u256(0)))
            cand_lines.append(
                f"- Address {h}: votes={v}, clarity={c}, creativity={cr}, relevance={r}, submission={json.dumps(sub)}"
            )

        if len(cand_lines) == 0:
            raise UserError("No submissions for given candidate set")

        cand_block = "\n".join(cand_lines)

        task = (
            "You are an impartial AI judge for a GenLayer writing game.\n"
            "You receive the round prompt, candidate set, their submissions, vote counts and AI sub-scores.\n"
            "Your job is to pick the MOST DESERVING winner.\n\n"
            f"Context / host reasoning: {json.dumps(context_reason)}\n\n"
            f"Round prompt: {json.dumps(prompt_text)}\n\n"
            "Candidates:\n"
            f"{cand_block}\n\n"
            "Rules:\n"
            "- You MUST choose winner among the candidate addresses listed above.\n"
            "- Consider BOTH human votes and AI scores (clarity/creativity/relevance).\n"
            "- You may override the host's original claim if it looks unfair.\n\n"
            "Return STRICT JSON with two fields:\n"
            '{\"winner\": \"<address_hex>\", \"explanation\": \"<short_reason>\"}\n'
            "No markdown, no ``` fences."
        )

        def leader() -> str:
            res = _prompt(task)
            return str(res)

        def validator(result) -> bool:
            try:
                raw = result.value  # type: ignore[attr-defined]
            except Exception:
                return False
            try:
                data = self._parse_json(str(raw))
            except Exception:
                return False

            w = data.get("winner")
            expl = data.get("explanation")
            if not isinstance(w, str) or not isinstance(expl, str):
                return False
            if w not in allowed_set:
                return False
            if len(expl) == 0 or len(expl) > 500:
                return False
            return True

        out = gl._nondet(leader, validator)
        data = self._parse_json(str(out))
        winner_hex = typing.cast(str, data["winner"])
        explanation = typing.cast(str, data.get("explanation", ""))

        for i in range(member_count):
            addr = self.session_member_at[self._mkey_idx(sid, i)]
            if addr.as_hex == winner_hex:
                return addr, explanation

        raise UserError("AI returned invalid winner")

    # -------------------------
    # public write: core game
    # -------------------------
    @gl.public.write
    def create_session(
        self,
        max_players: int,
        challenge_period_sec: int = 0,
        llm_prompts_enabled: bool = True,
        llm_judge_enabled: bool = True,
        appeal_bond_xp: int = 10,
        appeal_period_sec: int = 60,
    ) -> int:
        """
        Создать сессию.
        challenge_period_sec — окно для challenge'а победителя (optimistic claim).
        appeal_period_sec — окно для апелляций AI-оценок после скоринга.
        appeal_bond_xp — XP-бонд за одну апелляцию.
        """
        if max_players < 2:
            raise UserError("max_players must be >= 2")
        if challenge_period_sec < 0 or appeal_period_sec < 0 or appeal_bond_xp < 0:
            raise UserError("periods and bond must be >= 0")

        host = gl.message.sender_address

        sid = self.next_session_id
        if sid == u256(0):
            sid = u256(1)
        self.next_session_id = sid + u256(1)
        self.last_session_id = sid

        self.session_host[sid] = host
        self.session_max_players[sid] = u256(max_players)
        self.session_member_count[sid] = u256(1)
        self.session_round_no[sid] = u256(0)
        self.session_phase[sid] = self._PHASE_LOBBY()
        self.session_challenge_period_sec[sid] = u256(challenge_period_sec)
        self.session_llm_prompts_enabled[sid] = u256(1 if llm_prompts_enabled else 0)
        self.session_llm_judge_enabled[sid] = u256(1 if llm_judge_enabled else 0)
        self.session_appeal_bond_xp[sid] = u256(appeal_bond_xp)
        self.session_appeal_period_sec[sid] = u256(appeal_period_sec)
        self.session_active_claim_round[sid] = u256(0)

        # host auto-joins
        self.session_member_at[self._mkey_idx(sid, 0)] = host
        self.session_member_index[self._mkey(sid, host)] = u256(1)

        return int(sid)

    @gl.public.write
    def join_session(self, session_id: int) -> None:
        sid = self._sid(session_id)
        self._require_session(sid)

        sender = gl.message.sender_address
        if self._is_member(sid, sender):
            raise UserError("Already joined")

        cur = self.session_member_count.get(sid, u256(0))
        maxp = self.session_max_players[sid]
        if cur >= maxp:
            raise UserError("Session is full")

        idx = int(cur)
        self.session_member_at[self._mkey_idx(sid, idx)] = sender
        self.session_member_index[self._mkey(sid, sender)] = u256(idx + 1)
        self.session_member_count[sid] = cur + u256(1)

    @gl.public.write
    def start_round(self, session_id: int, prompt: str = "") -> int:
        """
        Старт раунда из LOBBY.
        Если prompt пустой и LLM-промпт включён — генерируем его через _ai_generate_prompt.
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        self._require_host(sid)
        self._require_no_active_claim(sid)

        if self._phase(sid) != self._PHASE_LOBBY():
            raise UserError("Round already running")

        rnd = self.session_round_no.get(sid, u256(0)) + u256(1)
        self.session_round_no[sid] = rnd

        rk = self._rk(sid, rnd)

        if prompt.strip() == "":
            if self.session_llm_prompts_enabled.get(sid, u256(0)) == u256(1):
                prompt_text = self._ai_generate_prompt(sid, rnd)
            else:
                prompt_text = f"Round {int(rnd)}: explain GenLayer in ONE sentence."
        else:
            prompt_text = prompt

        self.round_prompt[rk] = prompt_text
        self.round_finalized[rk] = u256(0)
        self.round_scored[rk] = u256(0)
        self.round_challenge_count[rk] = u256(0)
        self.session_phase[sid] = self._PHASE_SUBMISSIONS()

        return int(rnd)

    @gl.public.write
    def submit(self, session_id: int, text: str) -> None:
        """
        Участник отправляет ответ в фазе SUBMISSIONS.
        """
        sid = self._sid(session_id)
        self._require_session(sid)

        sender = gl.message.sender_address
        self._require_member(sid, sender)

        if self._phase(sid) != self._PHASE_SUBMISSIONS():
            raise UserError("Not in submissions phase")

        rnd = self._require_round_exists(sid)

        sk = self._skey(sid, rnd, sender)
        if self.round_has_submitted.get(sk, u256(0)) == u256(1):
            raise UserError("Already submitted")
        if text.strip() == "":
            raise UserError("Empty submission")

        self.round_submission[sk] = text
        self.round_has_submitted[sk] = u256(1)
        self.season_xp[sender] = self.season_xp.get(sender, u256(0)) + u256(1)

    @gl.public.write
    def submit_with_llm(self, session_id: int) -> None:
        """
        Сабмит с автогенерацией ответа через LLM.
        """
        sid = self._sid(session_id)
        self._require_session(sid)

        sender = gl.message.sender_address
        self._require_member(sid, sender)

        if self._phase(sid) != self._PHASE_SUBMISSIONS():
            raise UserError("Not in submissions phase")

        rnd = self._require_round_exists(sid)
        sk = self._skey(sid, rnd, sender)
        if self.round_has_submitted.get(sk, u256(0)) == u256(1):
            raise UserError("Already submitted")

        prompt = self.round_prompt.get(self._rk(sid, rnd), "")
        if prompt == "":
            raise UserError("Missing prompt")

        text = self._ai_generate_submission(prompt)
        self.round_submission[sk] = text
        self.round_has_submitted[sk] = u256(1)
        self.season_xp[sender] = self.season_xp.get(sender, u256(0)) + u256(1)

    @gl.public.write
    def close_submissions(self, session_id: int) -> None:
        """
        Host закрывает приём ответов:
        - запускает AI-модерацию + AI-скоринг для всех сабмитов,
        - открывает окно апелляций AI-оценок,
        - переводит фазу в VOTING.
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        self._require_host(sid)

        if self._phase(sid) != self._PHASE_SUBMISSIONS():
            raise UserError("Not in submissions phase")

        rnd = self._require_round_exists(sid)
        rk = self._rk(sid, rnd)

        prompt = self.round_prompt.get(rk, "")
        member_count = int(self.session_member_count.get(sid, u256(0)))

        for i in range(member_count):
            addr = self.session_member_at[self._mkey_idx(sid, i)]
            sk = self._skey(sid, rnd, addr)
            if self.round_has_submitted.get(sk, u256(0)) != u256(1):
                continue

            # если уже есть оценки, не пересчитываем (на всякий случай)
            if self.round_scored.get(rk, u256(0)) == u256(1) and self.round_score_clarity.get(sk) is not None:
                continue

            answer = self.round_submission.get(sk, "")
            ok, c, cr, r = self._ai_moderate_and_score(prompt, answer)
            if ok:
                self.round_submission_valid[sk] = u256(1)
            else:
                self.round_submission_valid[sk] = u256(0)
            self.round_score_clarity[sk] = u256(c)
            self.round_score_creativity[sk] = u256(cr)
            self.round_score_relevance[sk] = u256(r)

        self.round_scored[rk] = u256(1)

        appeal_sec = self.session_appeal_period_sec.get(sid, u256(0))
        if appeal_sec > u256(0):
            self.round_appeal_deadline[rk] = self._now() + appeal_sec
        else:
            self.round_appeal_deadline[rk] = u256(0)

        self.session_phase[sid] = self._PHASE_VOTING()

    @gl.public.write
    def vote(self, session_id: int, candidate: str) -> None:
        """
        Голосование:
        - только в VOTING,
        - нельзя голосовать за себя,
        - голосующий и кандидат должны иметь валидные сабмиты,
        - один голос на адрес.
        """
        sid = self._sid(session_id)
        self._require_session(sid)

        voter = gl.message.sender_address
        self._require_member(sid, voter)

        if self._phase(sid) != self._PHASE_VOTING():
            raise UserError("Not in voting phase")

        rnd = self._require_round_exists(sid)
        rk = self._rk(sid, rnd)

        if self.round_finalized.get(rk, u256(0)) != u256(0):
            raise UserError("Voting closed")

        if self.round_scored.get(rk, u256(0)) != u256(1):
            raise UserError("Round not scored yet")

        cand_addr = Address(candidate)
        self._require_member(sid, cand_addr)

        if cand_addr == voter:
            raise UserError("No self-vote")

        voter_sk = self._skey(sid, rnd, voter)
        if self.round_has_submitted.get(voter_sk, u256(0)) != u256(1):
            raise UserError("Submit first, then vote")

        cand_sk = self._skey(sid, rnd, cand_addr)
        if self.round_has_submitted.get(cand_sk, u256(0)) != u256(1):
            raise UserError("Candidate did not submit")
        if self.round_submission_valid.get(cand_sk, u256(0)) != u256(1):
            raise UserError("Candidate submission invalid")

        vk = self._voter_key(sid, rnd, voter)
        if self.round_vote_of.get(vk) is not None:
            raise UserError("Already voted")

        cand_hex = cand_addr.as_hex
        self.round_vote_of[vk] = cand_hex
        tally_key = self._cand_key(sid, rnd, cand_hex)
        self.round_votes_for[tally_key] = self.round_votes_for.get(tally_key, u256(0)) + u256(1)

    # -------------------------
    # deterministic finalize (60% human / 40% AI)
    # -------------------------
    def _compute_winner_by_votes(self, sid: u256, rnd: u256) -> Address:
        """
        Чисто по голосам — используется для optimistic fallback.
        """
        member_count = int(self.session_member_count.get(sid, u256(0)))
        best_votes = u256(0)
        best_hex: typing.Optional[str] = None
        best_addr: typing.Optional[Address] = None
        found_any = False

        for i in range(member_count):
            addr = self.session_member_at[self._mkey_idx(sid, i)]
            sk = self._skey(sid, rnd, addr)
            if self.round_has_submitted.get(sk, u256(0)) != u256(1):
                continue
            if self.round_submission_valid.get(sk, u256(0)) != u256(1):
                continue
            found_any = True
            h = addr.as_hex
            v = self.round_votes_for.get(self._cand_key(sid, rnd, h), u256(0))
            if (best_hex is None) or (v > best_votes) or (v == best_votes and h < best_hex):
                best_hex = h
                best_votes = v
                best_addr = addr

        if not found_any or best_addr is None:
            raise UserError("No submissions")
        return best_addr

    @gl.public.write
    def finalize_round(self, session_id: int) -> str:
        """
        Финализация раунда по формуле:
        final_score = 60% human_votes + 40% AI_scores (clarity+creativity+relevance).
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        self._require_host(sid)

        if self._phase(sid) != self._PHASE_VOTING():
            raise UserError("Not in voting phase")
        if self._active_claim_round(sid) != u256(0):
            raise UserError("Active claim pending; use finalize_claim")

        rnd = self._require_round_exists(sid)
        rk = self._rk(sid, rnd)

        status = self.round_finalized.get(rk, u256(0))
        if status == u256(1):
            return self.round_final_winner[rk].as_hex
        if status == u256(2):
            raise UserError("Claim pending; use finalize_claim")

        if self.round_scored.get(rk, u256(0)) != u256(1):
            raise UserError("Round not scored yet")

        # ждём окончания окна апелляций AI-оценок (если оно задано)
        appeal_deadline = self.round_appeal_deadline.get(rk, u256(0))
        if appeal_deadline != u256(0) and self._now() <= appeal_deadline:
            raise UserError("Appeal window still open")

        member_count = int(self.session_member_count.get(sid, u256(0)))
        if member_count == 0:
            raise UserError("No members")

        # собираем кандидатов
        candidates: list[tuple[Address, int, int]] = []  # (addr, votes, ai_total)
        max_votes = 0
        max_ai = 0

        for i in range(member_count):
            addr = self.session_member_at[self._mkey_idx(sid, i)]
            sk = self._skey(sid, rnd, addr)
            if self.round_has_submitted.get(sk, u256(0)) != u256(1):
                continue
            if self.round_submission_valid.get(sk, u256(0)) != u256(1):
                continue

            h = addr.as_hex
            votes = int(self.round_votes_for.get(self._cand_key(sid, rnd, h), u256(0)))
            c = int(self.round_score_clarity.get(sk, u256(0)))
            cr = int(self.round_score_creativity.get(sk, u256(0)))
            r = int(self.round_score_relevance.get(sk, u256(0)))
            ai_total = c + cr + r

            candidates.append((addr, votes, ai_total))
            if votes > max_votes:
                max_votes = votes
            if ai_total > max_ai:
                max_ai = ai_total

        if len(candidates) == 0:
            raise UserError("No valid submissions")

        best_score = -1
        best_hex: typing.Optional[str] = None
        best_addr: typing.Optional[Address] = None

        for addr, votes, ai_total in candidates:
            # нормализация в [0..1000]
            votes_scaled = (votes * 1000) // (max_votes if max_votes > 0 else 1)
            ai_scaled = (ai_total * 1000) // (max_ai if max_ai > 0 else 1)
            total_score = votes_scaled * 60 + ai_scaled * 40  # 60/40

            h = addr.as_hex
            if (best_addr is None) or (total_score > best_score) or (
                total_score == best_score and h < (best_hex or h)
            ):
                best_score = total_score
                best_hex = h
                best_addr = addr

        if best_addr is None:
            raise UserError("No winner")

        self.round_final_winner[rk] = best_addr
        self.round_finalized[rk] = u256(1)
        self.round_resolution_mode[rk] = u256(1)  # deterministic_finalize 60/40
        self.session_phase[sid] = self._PHASE_LOBBY()
        self.session_active_claim_round[sid] = u256(0)

        self.season_xp[best_addr] = self.season_xp.get(best_addr, u256(0)) + u256(10)
        self.season_wins[best_addr] = self.season_wins.get(best_addr, u256(0)) + u256(1)

        return best_addr.as_hex

    # -------------------------
    # Appeals of AI scores (XP bond)
    # -------------------------
    @gl.public.write
    def appeal_ai_score(self, session_id: int, round_no: int) -> int:
        """
        Игрок оспаривает AI-оценку СВОЕГО ответа:
        - вносит XP-бонд,
        - LLM пересчитывает оценки,
        - если новая сумма > старой — оценки обновляются, бонд умножается и возвращается,
        - иначе бонд сгорает.
        """
        sid = self._sid(session_id)
        self._require_session(sid)

        challenger = gl.message.sender_address
        self._require_member(sid, challenger)

        rnd = u256(round_no)
        rk = self._rk(sid, rnd)

        if self.round_scored.get(rk, u256(0)) != u256(1):
            raise UserError("Round not scored yet")
        if self.round_finalized.get(rk, u256(0)) == u256(1):
            raise UserError("Round already finalized")

        deadline = self.round_appeal_deadline.get(rk, u256(0))
        if deadline != u256(0) and self._now() > deadline:
            raise UserError("Appeal window closed")

        sk = self._skey(sid, rnd, challenger)
        if self.round_has_submitted.get(sk, u256(0)) != u256(1):
            raise UserError("No submission to appeal")
        if self.round_submission_valid.get(sk, u256(0)) != u256(1):
            raise UserError("Only valid submissions can be appealed")

        if self.submission_appealed.get(sk, u256(0)) == u256(1):
            raise UserError("Already appealed")

        bond = self.session_appeal_bond_xp.get(sid, u256(0))
        if bond > u256(0):
            cur_xp = self.season_xp.get(challenger, u256(0))
            if cur_xp < bond:
                raise UserError("Not enough XP for appeal bond")
            self.season_xp[challenger] = cur_xp - bond

        old_c = int(self.round_score_clarity.get(sk, u256(0)))
        old_cr = int(self.round_score_creativity.get(sk, u256(0)))
        old_r = int(self.round_score_relevance.get(sk, u256(0)))
        old_total = old_c + old_cr + old_r

        prompt = self.round_prompt.get(rk, "")
        answer = self.round_submission.get(sk, "")

        new_c, new_cr, new_r = self._ai_rescore_submission(prompt, answer)
        new_total = new_c + new_cr + new_r

        if new_total > old_total:
            # AI явно поднял оценку — считаем, что апелляция успешна
            self.round_score_clarity[sk] = u256(new_c)
            self.round_score_creativity[sk] = u256(new_cr)
            self.round_score_relevance[sk] = u256(new_r)
            if bond > u256(0):
                reward = bond * u256(2)
                self.season_xp[challenger] = self.season_xp.get(challenger, u256(0)) + reward
        # иначе: оставляем старые оценки, bond уже сгорел

        self.submission_appealed[sk] = u256(1)
        return new_total

    # -------------------------
    # optimistic claim flow (winner-level appeals)
    # -------------------------
    def _set_claim(self, sid: u256, rnd: u256, winner: Address, reason: str) -> None:
        rk = self._rk(sid, rnd)
        if self.round_finalized.get(rk, u256(0)) != u256(0):
            raise UserError("Round already finalized or claim pending")

        self.round_claimed_winner[rk] = winner
        self.round_claim_reason[rk] = reason
        deadline = self._now() + self.session_challenge_period_sec.get(sid, u256(0))
        self.round_claim_deadline[rk] = deadline
        self.round_challenge_count[rk] = u256(0)

        self.round_finalized[rk] = u256(2)          # CLAIM_PENDING
        self.session_active_claim_round[sid] = rnd  # блокируем новый раунд
        self.session_phase[sid] = self._PHASE_LOBBY()

    @gl.public.write
    def optimistic_claim_winner(self, session_id: int, candidate: str, reason: str = "") -> str:
        """
        Host делает optimistic claim явного победителя (адрес).
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        self._require_host(sid)

        if self._active_claim_round(sid) != u256(0):
            raise UserError("There is already an active claim")
        if self._phase(sid) != self._PHASE_VOTING():
            raise UserError("Claim allowed only in VOTING phase")

        rnd = self._require_round_exists(sid)
        cand_addr = Address(candidate)
        self._require_member(sid, cand_addr)

        sk = self._skey(sid, rnd, cand_addr)
        if self.round_has_submitted.get(sk, u256(0)) != u256(1):
            raise UserError("Candidate did not submit")
        if self.round_submission_valid.get(sk, u256(0)) != u256(1):
            raise UserError("Candidate submission invalid")

        self._set_claim(sid, rnd, cand_addr, reason)
        return cand_addr.as_hex

    @gl.public.write
    def optimistic_claim_by_votes(self, session_id: int) -> str:
        """
        Host делает claim победителя по on-chain голосам.
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        self._require_host(sid)

        if self._active_claim_round(sid) != u256(0):
            raise UserError("There is already an active claim")
        if self._phase(sid) != self._PHASE_VOTING():
            raise UserError("Claim allowed only in VOTING phase")

        rnd = self._require_round_exists(sid)
        w = self._compute_winner_by_votes(sid, rnd)
        self._set_claim(sid, rnd, w, "Claimed by on-chain vote tally")
        return w.as_hex

    @gl.public.write
    def optimistic_claim_by_llm(self, session_id: int) -> str:
        """
        Host делает claim победителя, выбранного LLM среди всех валидных сабмиттеров.
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        self._require_host(sid)

        if self.session_llm_judge_enabled.get(sid, u256(0)) != u256(1):
            raise UserError("LLM judge disabled for this session")
        if self._active_claim_round(sid) != u256(0):
            raise UserError("There is already an active claim")
        if self._phase(sid) != self._PHASE_VOTING():
            raise UserError("Claim allowed only in VOTING phase")

        rnd = self._require_round_exists(sid)
        rk = self._rk(sid, rnd)

        if self.round_scored.get(rk, u256(0)) != u256(1):
            raise UserError("Round not scored yet")

        member_count = int(self.session_member_count.get(sid, u256(0)))
        cand_hexes: list[str] = []

        for i in range(member_count):
            addr = self.session_member_at[self._mkey_idx(sid, i)]
            sk = self._skey(sid, rnd, addr)
            if self.round_has_submitted.get(sk, u256(0)) != u256(1):
                continue
            if self.round_submission_valid.get(sk, u256(0)) != u256(1):
                continue
            cand_hexes.append(addr.as_hex)

        if len(cand_hexes) == 0:
            raise UserError("No submissions")

        w_addr, _expl = self._ai_pick_winner_from_set(
            sid, rnd, cand_hexes, "Initial claim by LLM judge"
        )

        self._set_claim(sid, rnd, w_addr, "Claimed by LLM judge")
        return w_addr.as_hex

    @gl.public.write
    def challenge_claim(self, session_id: int, alternative_winner: str, reason: str) -> int:
        """
        Любой участник может оспорить активный claim (альтернативный победитель + причина).
        """
        sid = self._sid(session_id)
        self._require_session(sid)

        challenger = gl.message.sender_address
        self._require_member(sid, challenger)

        rnd = self._active_claim_round(sid)
        if rnd == u256(0):
            raise UserError("No active claim")

        rk = self._rk(sid, rnd)
        if self.round_finalized.get(rk, u256(0)) != u256(2):
            raise UserError("No active claim")

        if self._now() > self.round_claim_deadline.get(rk, u256(0)):
            raise UserError("Challenge window closed")

        cbk = self._challenged_by_key(sid, rnd, challenger)
        if self.round_challenged_by.get(cbk, u256(0)) == u256(1):
            raise UserError("Already challenged")

        alt = Address(alternative_winner)
        self._require_member(sid, alt)

        alt_sk = self._skey(sid, rnd, alt)
        if self.round_has_submitted.get(alt_sk, u256(0)) != u256(1):
            raise UserError("Alternative winner did not submit")
        if self.round_submission_valid.get(alt_sk, u256(0)) != u256(1):
            raise UserError("Alternative submission invalid")

        if reason.strip() == "":
            raise UserError("Empty reason")

        idx = int(self.round_challenge_count.get(rk, u256(0)))
        self.round_challenge_who[self._chk_key(sid, rnd, idx)] = challenger
        self.round_challenge_alt[self._chk_key(sid, rnd, idx)] = alt
        self.round_challenge_reason[self._chk_key(sid, rnd, idx)] = reason
        self.round_challenge_count[rk] = u256(idx + 1)
        self.round_challenged_by[cbk] = u256(1)

        return idx

    @gl.public.write
    def finalize_claim(self, session_id: int) -> str:
        """
        Финализация optimistic-claim:
        - если нет челленджей → принимаем claim,
        - если есть → после дедлайна LLM выбирает победителя среди claimed+alts
          (или fallback по голосам, если LLM-судья отключён).
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        self._require_host(sid)

        rnd = self._active_claim_round(sid)
        if rnd == u256(0):
            raise UserError("No active claim")

        rk = self._rk(sid, rnd)
        if self.round_finalized.get(rk, u256(0)) != u256(2):
            raise UserError("No active claim")

        claimed = self.round_claimed_winner.get(rk)
        if claimed is None:
            raise UserError("No claimed winner")

        challenge_count = int(self.round_challenge_count.get(rk, u256(0)))
        deadline = self.round_claim_deadline.get(rk, u256(0))

        if challenge_count > 0 and self._now() <= deadline:
            raise UserError("Wait until challenge window ends")

        # желательно, чтобы окно апелляций AI-оценок тоже уже закрылось
        appeal_deadline = self.round_appeal_deadline.get(rk, u256(0))
        if appeal_deadline != u256(0) and self._now() <= appeal_deadline:
            raise UserError("AI-score appeal window still open")

        winner: Address = claimed
        mode: u256 = u256(2)
        explanation = "Accepted host claim (no challenges)."

        if challenge_count > 0:
            cand_hexes: list[str] = [claimed.as_hex]
            for i in range(challenge_count):
                alt = self.round_challenge_alt[self._chk_key(sid, rnd, i)]
                h = alt.as_hex
                if h not in cand_hexes:
                    cand_hexes.append(h)

            if self.session_llm_judge_enabled.get(sid, u256(0)) == u256(1):
                reason = "Disputed claim: host + challengers provided alternatives."
                winner, explanation = self._ai_pick_winner_from_set(
                    sid, rnd, cand_hexes, reason
                )
                mode = u256(3)  # llm_override
            else:
                winner = self._compute_winner_by_votes(sid, rnd)
                mode = u256(4)  # votes_fallback
                explanation = "Fallback to on-chain vote tally (LLM judge disabled)."

        self.round_final_winner[rk] = winner
        self.round_finalized[rk] = u256(1)
        self.round_resolution_mode[rk] = mode
        self.round_llm_explanation[rk] = explanation
        self.session_active_claim_round[sid] = u256(0)
        self.session_phase[sid] = self._PHASE_LOBBY()

        self.season_xp[winner] = self.season_xp.get(winner, u256(0)) + u256(10)
        self.season_wins[winner] = self.season_wins.get(winner, u256(0)) + u256(1)

        return winner.as_hex

    # -------------------------
    # XP helpers
    # -------------------------
    @gl.public.write
    def reward_player(self, session_id: int, round_no: int, player: str, amount: int) -> None:
        """
        Host вручную добавляет XP игроку за конкретный раунд, если у него был сабмит.
        """
        if amount <= 0:
            raise UserError("amount must be > 0")

        sid = self._sid(session_id)
        self._require_session(sid)
        self._require_host(sid)

        rnd = u256(round_no)
        addr = Address(player)
        self._require_member(sid, addr)

        sk = self._skey(sid, rnd, addr)
        if self.round_has_submitted.get(sk, u256(0)) != u256(1):
            raise UserError("Player did not submit in that round")

        self.season_xp[addr] = self.season_xp.get(addr, u256(0)) + u256(amount)

    @gl.public.write
    def add_xp(self, player: str, amount: int) -> None:
        """
        Utility: прямое начисление XP (например, внешней системой).
        """
        if amount <= 0:
            raise UserError("amount must be > 0")
        addr = Address(player)
        cur = self.season_xp.get(addr, u256(0))
        self.season_xp[addr] = cur + u256(amount)

    # -------------------------
    # public view
    # -------------------------
    @gl.public.view
    def get_next_session_id(self) -> int:
        return int(self.next_session_id)

    @gl.public.view
    def get_last_session_id(self) -> int:
        nid = self.next_session_id
        if nid <= u256(1):
            return 0
        return int(nid - u256(1))

    @gl.public.view
    def get_session(self, session_id: int) -> dict[str, typing.Any]:
        sid = self._sid(session_id)
        self._require_session(sid)
        return {
            "session_id": int(sid),
            "host": self.session_host[sid].as_hex,
            "max_players": int(self.session_max_players[sid]),
            "member_count": int(self.session_member_count.get(sid, u256(0))),
            "round_no": int(self.session_round_no.get(sid, u256(0))),
            "phase": int(self._phase(sid)),
            "challenge_period_sec": int(self.session_challenge_period_sec.get(sid, u256(0))),
            "appeal_period_sec": int(self.session_appeal_period_sec.get(sid, u256(0))),
            "appeal_bond_xp": int(self.session_appeal_bond_xp.get(sid, u256(0))),
            "llm_prompts_enabled": int(self.session_llm_prompts_enabled.get(sid, u256(0))),
            "llm_judge_enabled": int(self.session_llm_judge_enabled.get(sid, u256(0))),
            "active_claim_round": int(self._active_claim_round(sid)),
        }

    @gl.public.view
    def is_member(self, session_id: int, player: str) -> bool:
        sid = self._sid(session_id)
        self._require_session(sid)
        return self._is_member(sid, Address(player))

    @gl.public.view
    def get_member_at(self, session_id: int, index: int) -> str:
        sid = self._sid(session_id)
        self._require_session(sid)
        count = int(self.session_member_count.get(sid, u256(0)))
        if index < 0 or index >= count:
            raise UserError("index out of range")
        return self.session_member_at[self._mkey_idx(sid, index)].as_hex

    @gl.public.view
    def get_round_prompt(self, session_id: int, round_no: int) -> str:
        sid = self._sid(session_id)
        self._require_session(sid)
        return self.round_prompt.get(self._rk(sid, u256(round_no)), "")

    @gl.public.view
    def get_submission(self, session_id: int, round_no: int, player: str) -> str:
        sid = self._sid(session_id)
        self._require_session(sid)
        addr = Address(player)
        return self.round_submission.get(self._skey(sid, u256(round_no), addr), "")

    @gl.public.view
    def list_round_submissions(self, session_id: int, round_no: int) -> list[dict[str, typing.Any]]:
        """
        Список всех сабмитов (для UI/leaderboard):
        author, text, valid, votes, clarity/creativity/relevance.
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        rnd = u256(round_no)
        member_count = int(self.session_member_count.get(sid, u256(0)))

        out: list[dict[str, typing.Any]] = []
        for i in range(member_count):
            addr = self.session_member_at[self._mkey_idx(sid, i)]
            sk = self._skey(sid, rnd, addr)
            if self.round_has_submitted.get(sk, u256(0)) != u256(1):
                continue
            h = addr.as_hex
            votes = int(self.round_votes_for.get(self._cand_key(sid, rnd, h), u256(0)))
            valid = int(self.round_submission_valid.get(sk, u256(0))) == 1
            out.append(
                {
                    "author": h,
                    "text": self.round_submission.get(sk, ""),
                    "valid": valid,
                    "votes": votes,
                    "clarity": int(self.round_score_clarity.get(sk, u256(0))),
                    "creativity": int(self.round_score_creativity.get(sk, u256(0))),
                    "relevance": int(self.round_score_relevance.get(sk, u256(0))),
                }
            )
        return out

    @gl.public.view
    def get_votes_for(self, session_id: int, round_no: int, candidate: str) -> int:
        sid = self._sid(session_id)
        self._require_session(sid)
        rnd = u256(round_no)
        cand_hex = Address(candidate).as_hex
        return int(self.round_votes_for.get(self._cand_key(sid, rnd, cand_hex), u256(0)))

    @gl.public.view
    def get_round_info(self, session_id: int, round_no: int) -> dict[str, typing.Any]:
        """
        Расширенный статус раунда: промпт, финализация, claim, LLM-объяснение.
        """
        sid = self._sid(session_id)
        self._require_session(sid)
        rnd = u256(round_no)
        rk = self._rk(sid, rnd)

        finalw = self.round_final_winner.get(rk)
        claimed = self.round_claimed_winner.get(rk)

        return {
            "prompt": self.round_prompt.get(rk, ""),
            "finalized_status": int(self.round_finalized.get(rk, u256(0))),
            "claim_deadline": int(self.round_claim_deadline.get(rk, u256(0))),
            "claim_reason": self.round_claim_reason.get(rk, ""),
            "claimed_winner": None if claimed is None else claimed.as_hex,
            "challenge_count": int(self.round_challenge_count.get(rk, u256(0))),
            "final_winner": None if finalw is None else finalw.as_hex,
            "resolution_mode": int(self.round_resolution_mode.get(rk, u256(0))),
            "llm_explanation": self.round_llm_explanation.get(rk, ""),
            "appeal_deadline": int(self.round_appeal_deadline.get(rk, u256(0))),
        }

    @gl.public.view
    def get_round_winner(self, session_id: int, round_no: int) -> typing.Optional[str]:
        sid = self._sid(session_id)
        self._require_session(sid)
        rk = self._rk(sid, u256(round_no))
        w = self.round_final_winner.get(rk)
        return None if w is None else w.as_hex

    @gl.public.view
    def get_xp(self, player: str) -> int:
        addr = Address(player)
        return int(self.season_xp.get(addr, u256(0)))

    @gl.public.view
    def get_my_xp(self) -> int:
        return int(self.season_xp.get(gl.message.sender_address, u256(0)))

    @gl.public.view
    def get_wins(self, player: str) -> int:
        addr = Address(player)
        return int(self.season_wins.get(addr, u256(0)))

    # -------------------------
    # constructor
    # -------------------------
    def __init__(self):
        self.next_session_id = u256(1)
        self.last_session_id = u256(0)
