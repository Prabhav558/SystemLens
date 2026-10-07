"""The thing that keeps this usable: 100 identical errors must produce
exactly 1 analysis, not 100 LLM calls.
"""
from systemlens.config import RateLimitConfig
from systemlens.core.ratelimit import RateLimiter
from systemlens.memory.store import ProjectStore


def test_hundred_identical_errors_yield_one_analysis(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    config = RateLimitConfig(cooldown_seconds=1800, max_analyses_per_hour=20,
                              daily_token_budget=500_000, reanalyze_on_state_change=False)
    limiter = RateLimiter(config, store)

    fingerprint = "abc123"
    allowed_count = 0
    for _ in range(100):
        store.touch_fingerprint(fingerprint, "template", "generic")
        decision = limiter.check(fingerprint, state_changed=False)
        if decision.allow:
            allowed_count += 1
            # simulate the pipeline actually running the analysis
            from systemlens.core.models import Analysis
            store.record_incident(fingerprint, Analysis(
                verdict="root_cause_identified", root_cause="x", affected_component="y",
                evidence=[], fix_suggestion="z", confidence=0.5), "fake", "fake-model")
            store.mark_analyzed(fingerprint)

    assert allowed_count == 1
    store.close()


def test_state_change_bypasses_cooldown_when_enabled(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    config = RateLimitConfig(cooldown_seconds=1800, max_analyses_per_hour=20,
                              daily_token_budget=500_000, reanalyze_on_state_change=True,
                              min_reanalyze_seconds=0)
    limiter = RateLimiter(config, store)
    fingerprint = "abc123"

    store.touch_fingerprint(fingerprint, "template", "generic")
    d1 = limiter.check(fingerprint, state_changed=False)
    assert d1.allow
    store.mark_analyzed(fingerprint)

    # immediately re-checking with no state change: on cooldown
    d2 = limiter.check(fingerprint, state_changed=False)
    assert not d2.allow
    assert d2.reason == "fingerprint_on_cooldown"

    # but if the correlated container state actually changed, bypass it
    d3 = limiter.check(fingerprint, state_changed=True)
    assert d3.allow
    assert d3.reason == "cooldown_bypassed_state_changed"


def test_hourly_cap_blocks_further_analysis(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    config = RateLimitConfig(cooldown_seconds=0, max_analyses_per_hour=2,
                              daily_token_budget=500_000, reanalyze_on_state_change=False)
    limiter = RateLimiter(config, store)

    from systemlens.core.models import Analysis
    for i in range(2):
        fp = f"fp-{i}"
        store.touch_fingerprint(fp, "t", "generic")
        assert limiter.check(fp, False).allow
        store.record_incident(fp, Analysis(verdict="root_cause_identified", root_cause="x",
                                            affected_component="y", evidence=[],
                                            fix_suggestion="z", confidence=0.5), "fake", "m")

    store.touch_fingerprint("fp-3", "t", "generic")
    decision = limiter.check("fp-3", False)
    assert not decision.allow
    assert decision.reason == "hourly_analysis_cap_reached"


def test_daily_token_budget_exhausted(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    config = RateLimitConfig(cooldown_seconds=0, max_analyses_per_hour=100,
                              daily_token_budget=1000, reanalyze_on_state_change=False)
    limiter = RateLimiter(config, store)
    limiter.record_spend(1500)

    store.touch_fingerprint("fp", "t", "generic")
    decision = limiter.check("fp", False)
    assert not decision.allow
    assert decision.reason == "daily_token_budget_exhausted"


def test_state_change_bypass_respects_the_reanalysis_floor(tmp_path):
    """A crash-looping container changes state on every restart; without a
    floor each restart would bypass the cooldown and cost an analysis.
    """
    store = ProjectStore(tmp_path / "state.db")
    config = RateLimitConfig(cooldown_seconds=1800, reanalyze_on_state_change=True,
                              min_reanalyze_seconds=120)
    limiter = RateLimiter(config, store)
    store.touch_fingerprint("fp", "t", "generic")
    store.mark_analyzed("fp")

    assert not limiter.check("fp", state_changed=True).allow


def test_memory_answers_are_exempt_from_llm_budgets(tmp_path):
    store = ProjectStore(tmp_path / "state.db")
    config = RateLimitConfig(cooldown_seconds=0, max_analyses_per_hour=100, daily_token_budget=10)
    limiter = RateLimiter(config, store)
    limiter.record_spend(50)
    store.touch_fingerprint("fp", "t", "generic")

    assert not limiter.check("fp", False).allow
    assert limiter.check("fp", False, free=True).allow
