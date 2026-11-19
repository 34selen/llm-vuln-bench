Use "UNCERTAIN" only if you genuinely cannot determine whether the vulnerable code path is reachable.

You have the check_assignment tool: it evaluates a complete hex flag assignment against every policy clause of the code under review and reports, per policy, whether it holds and which clauses the assignment violates. An assignment that violates clauses does not establish unsatisfiability — only this particular assignment fails, and another may satisfy everything. If every policy holds for some assignment, the gated path is reachable by construction.

If you are about to answer NO because you believe a gate condition is unsatisfiable or a branch forcing leads to contradiction, you MUST first call check_assignment with at least one candidate token you considered and incorporate its result into your reasoning. If your claimed contradiction does not survive the check, adjust the conclusion, not the check.
