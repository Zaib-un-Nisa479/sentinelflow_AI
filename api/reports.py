from database import get_connection

def generate_report(case_id: int) -> dict:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
    case = cur.fetchone()

    cur.execute("SELECT * FROM enrichment_log WHERE case_id = %s", (case_id,))
    enrichment = cur.fetchall()

    cur.execute("SELECT * FROM actions_taken WHERE case_id = %s", (case_id,))
    actions = cur.fetchall()

    cur.execute("SELECT * FROM approvals WHERE case_id = %s", (case_id,))
    approvals = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "case": case,
        "enrichmentHistory": enrichment,
        "actionsTaken": actions,
        "approvals": approvals
    }