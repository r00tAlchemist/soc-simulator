from __future__ import annotations
from models import LogEntry, Scenario, SessionResult


class Scorer:
    def score(
        self,
        user_answer: str,
        techniques_guessed: list[str],
        scenario: Scenario,
        logs: list[LogEntry],
        time_taken: float,
    ) -> SessionResult:
        meta = scenario.meta
        true_answer = meta.answer
        is_correct = user_answer.upper() == true_answer.upper()

        score = 0
        breakdown: list[dict] = []

        verdict_pts = meta.scoring_correct_verdict if is_correct else 0
        score += verdict_pts
        breakdown.append({"item": "Correct verdict", "points": verdict_pts})

        time_bonus = 0
        if meta.scoring_time_bonus:
            if time_taken < 180:
                time_bonus = 50
            elif time_taken < 300:
                time_bonus = 25
        score += time_bonus
        breakdown.append({"item": "Time bonus", "points": time_bonus})

        result = SessionResult(
            scenario_name=meta.name,
            true_answer=true_answer,
            user_answer=user_answer,
            is_correct=is_correct,
            score=score,
            time_taken_seconds=time_taken,
            phase_breakdown=breakdown,
            techniques_identified=[],
        )

        self._print_debrief(result, scenario, logs)
        return result

    def _print_debrief(self, result: SessionResult, scenario: Scenario, logs: list[LogEntry]) -> None:
        sep = "=" * 65
        print(f"\n{sep}")
        print("  DEBRIEF")
        print(sep)

        verdict_icon = "✓" if result.is_correct else "✗"
        print(f"\n  Verdict:  {verdict_icon} {result.user_answer.upper()} (true: {result.true_answer})")
        print(f"  Time:     {result.time_taken_seconds:.1f}s")
        print(f"  Score:    {result.score}")

        print("\n  Score breakdown:")
        for item in result.phase_breakdown:
            print(f"    {item['item']:45s} +{item['points']}")

        notable = [l for l in logs if l._is_attack or (scenario.is_clean and l._phase_id)]
        if notable:
            phases_seen: dict[str, list[LogEntry]] = {}
            for l in notable:
                phases_seen.setdefault(l._phase_id, []).append(l)
            label = "What triggered the alert (benign activity):" if scenario.is_clean else "Attack phases injected:"
            print(f"\n  {label}")
            for phase_id, entries in phases_seen.items():
                phase_name = next(
                    (p.name for p in scenario.phases if p.id == phase_id), phase_id
                )
                print(f"    {entries[0].timestamp.strftime('%H:%M:%S')}  {phase_name}  ({len(entries)} events)")

        if scenario.meta.mitre_techniques:
            print("\n  MITRE ATT&CK — techniques present in this scenario:")
            for t in scenario.meta.mitre_techniques:
                print(f"    {t.id:14s}  {t.name:42s}  {t.url}")

        print(f"\n  Hint: {scenario.meta.hint}")
        print(sep + "\n")
