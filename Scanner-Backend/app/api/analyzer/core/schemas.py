# from typing import List, Dict, Optional
# from pydantic import BaseModel

# # class ScanScoreResponse(BaseModel):
# #     scan_id: str
# #     domain_score: int
# #     categorized_vulnerabilities: Dict[str, Dict[str, List[str]]]

# #     class Config:
# #         from_attributes = True 

# class VulnerabilityEntry(BaseModel):
#     subdomain: str
#     ip: Optional[str] = None
#     severity: str
#     port: Optional[int] = None

# class ScanScoreResponse(BaseModel):
#     scan_id: str
#     domain_score: int
#     host : dict
#     severity: str
#     categorized_vulnerabilities: Dict[str, Dict[str, List[VulnerabilityEntry]]]
#     ips: List[str]

#     class Config:
#         from_attributes = True
from pydantic import BaseModel
import time


class AnalyserResult(BaseModel):
    score: int = 100
    domain: str = ""
    result: dict = {}
    timestamp: int = int(time.time())

class CategoryResult(BaseModel):
    penalty_score: int = 0
    category: str = ""
    details: dict = {}

class PipelineResult(BaseModel):
    penalty_score: int = 0
    details: dict = {}