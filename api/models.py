from typing import Literal, Optional

from pydantic import BaseModel

# Restricting this to a known set means FastAPI rejects a typo'd or bogus
# ioc_type (e.g. "ipaddress", "domian") before it ever reaches enrichment
# logic, instead of silently mis-scoring it.
IocType = Literal["ip", "domain", "hash", "url"]


class EnrichRequest(BaseModel):
    ioc: str
    ioc_type: Optional[IocType] = "ip"


class ActionRequest(BaseModel):
    case_id: int
    action_type: Literal["block_ip", "isolate_host", "log_only"]
    executed_by: Literal["agent_auto", "human_approved"]


class ReportRequest(BaseModel):
    case_id: int