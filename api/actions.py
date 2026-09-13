from database import get_connection
from datetime import datetime

def execute_action(case_id: int, action_type: str, executed_by: str) -> dict:
    """
    SIMULATED action — this never touches a real firewall.
    In production, this function's internals would call a real firewall/EDR API.
    The interface (what calls it, what it returns) stays identical either way —
    that's the point of this abstraction.
    """
    conn = get_connection()
    cur = conn.cursor()

    # Simulate the action (just logging + a fake "success")
    result = f"SIMULATED: {action_type} executed successfully (not a real action)"

    cur.execute(
        """INSERT INTO actions_taken (case_id, action_type, executed_by, result)
           VALUES (%s, %s, %s, %s) RETURNING id""",
        (case_id, action_type, executed_by, result)
    )
    action_id = cur.fetchone()["id"]

    cur.execute(
        "UPDATE cases SET status = %s, resolved_at = %s WHERE id = %s",
        ("auto_resolved" if executed_by == "agent_auto" else "escalated", datetime.utcnow(), case_id)
    )

    conn.commit()
    cur.close()
    conn.close()

    return {"actionId": action_id, "result": result}