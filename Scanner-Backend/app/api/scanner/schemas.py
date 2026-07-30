from pydantic import BaseModel


class ScanRequest(BaseModel):
    domain: str


class CancelScanRequest(BaseModel):
    domain: str
