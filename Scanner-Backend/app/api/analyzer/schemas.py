from typing import List, Dict, Optional
from pydantic import BaseModel

class OrgHistoryRequest(BaseModel):
    org_id: str

class GetScoreRequest(BaseModel):
    domain: str