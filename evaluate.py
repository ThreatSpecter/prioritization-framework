"""Evaluate all five prioritization models against the objective function."""

from __future__ import annotations

from pathlib import Path

from prioritization import (
    MODEL_REGISTRY,
    evaluate_objective_function,
    evaluate_risk_objective_function,
    load_benchmark_corpus,
    prioritize_corpus_risks,
)


def main() -> None:
    corpus_path = Path(__file__).parent / "data" / "benchmark_corpus.json"
    features, risks = load_benchmark_corpus(corpus_path)

    print(f"Benchmark Corpus: {len(features)} visible threats, {len(risks)} risks\n")
    print(f"{'Model':42s} | {'Crit':>11s} | {'High':>11s} | {'Med':>4s} | {'Low':>4s} | {'Pass':>5s} | {'Penalty':>7s}")
    print("-" * 102)
    for mname, fn in MODEL_REGISTRY.items():
        evaluated = [(f, fn(f)) for f in features]
        res = evaluate_objective_function(mname, evaluated)
        c_str = f"{res.counts['critical']:3d} ({res.pct_critical*100:4.1f}%)"
        h_str = f"{res.counts['high']:3d} ({res.pct_high*100:4.1f}%)"
        print(
            f"{mname:42s} | {c_str:>11s} | {h_str:>11s} | {res.counts['medium']:4d} | {res.counts['low']:4d} | "
            f"{str(res.passed):>5s} | {res.score:7.2f}"
        )

    print("\nRisk Objective Function (Model 5):")
    priorities = prioritize_corpus_risks(features, risks)
    r_res = evaluate_risk_objective_function(priorities)
    print(
        f"  Total={r_res.total} | P0={r_res.counts['P0']} ({r_res.pct_p0*100:.1f}%) | "
        f"P1={r_res.counts['P1']} ({r_res.pct_p1*100:.1f}%) | P2={r_res.counts['P2']} | "
        f"P3={r_res.counts['P3']} | Unrated={r_res.counts['Not yet prioritised']} | Passed={r_res.passed}"
    )


if __name__ == "__main__":
    main()
