"""
CLI entry-point for the Azure Policy Gate engine.

Usage:
    python -m policy_engine.main <path-to-tfplan.json>

Exit codes:
    0  -- All checks passed (no HIGH severity violations)
    1  -- HIGH severity violations found -> pipeline should fail
    2  -- Input / runtime error
"""

import io
import os
import sys

from policy_engine.engine import evaluate_plan
from policy_engine.reporter import format_markdown, post_pr_comment, log_to_table_storage


from policy_engine.config import PolicyConfigError


def _safe_print(*args, **kwargs):
    """Print with fallback for consoles that cannot render Unicode."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        text = " ".join(str(a) for a in args)
        print(text.encode("ascii", errors="replace").decode("ascii"), **kwargs)


def main() -> int:
    # Force UTF-8 output where possible
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace"
            )
        except Exception:
            pass

    if len(sys.argv) < 2:
        _safe_print("Usage: python -m policy_engine.main <tfplan.json>", file=sys.stderr)
        return 2

    plan_path = sys.argv[1]

    if not os.path.isfile(plan_path):
        _safe_print(f"Error: file not found: {plan_path}", file=sys.stderr)
        return 2

    # -- Run the engine ------------------------------------------------
    _safe_print(f"\n{'=' * 60}")
    _safe_print(f"  Azure Policy Gate -- Evaluating {plan_path}")
    _safe_print(f"{'=' * 60}\n")

    try:
        result = evaluate_plan(plan_path)
    except PolicyConfigError as exc:
        _safe_print(f"Configuration Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        _safe_print(f"Error evaluating plan: {exc}", file=sys.stderr)
        return 2

    # -- Console output ------------------------------------------------
    _safe_print(result.summary)
    _safe_print()

    for v in result.violations:
        sev = v.severity.value
        icon = {"HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[i]"}.get(sev, "[?]")
        _safe_print(f"  {icon} [{v.rule_id}] {v.resource_address}")
        _safe_print(f"      {v.message}")
        _safe_print()

    # -- Markdown output (also written to file for pipeline artifact) --
    md = format_markdown(result)
    md_path = os.environ.get("POLICY_REPORT_PATH", "policy-report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    _safe_print(f"[main] Markdown report written to {md_path}")

    # -- PR comment (only in pipeline context) -------------------------
    post_pr_comment(result)

    # -- Table Storage logging -----------------------------------------
    pr_number = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID", "")
    repository = os.environ.get("BUILD_REPOSITORY_NAME", "")
    log_to_table_storage(result, pr_number=pr_number, repository=repository)

    # -- Exit code -----------------------------------------------------
    if result.has_high_severity:
        _safe_print("\n[FAIL] HIGH severity violations detected -- pipeline FAILED.\n")
        return 1

    _safe_print("\n[PASS] All checks passed.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
