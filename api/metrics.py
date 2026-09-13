from database import get_connection

def get_dashboard_metrics() -> dict:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as count FROM cases WHERE status = 'open'")
    open_cases = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) as count FROM cases WHERE status = 'auto_resolved'")
    auto_resolved = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) as count FROM cases")
    total = cur.fetchone()["count"]

    cur.execute("""
        SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))) as avg_seconds
        FROM cases WHERE resolved_at IS NOT NULL
    """)
    mttr_row = cur.fetchone()
    mttr_seconds = mttr_row["avg_seconds"] or 0

    cur.close()
    conn.close()

    auto_resolution_rate = (auto_resolved / total * 100) if total > 0 else 0

    return {
        "openCases": open_cases,
        "autoResolvedCases": auto_resolved,
        "totalCases": total,
        "mttrSeconds": round(mttr_seconds, 1),
        "autoResolutionRatePercent": round(auto_resolution_rate, 1)
    }