from pydantic import BaseModel
from typing import Dict, Optional

class UserAssessmentData(BaseModel):
    authentication: Optional[Dict[str, bool]] = None
    web_browsing: Optional[Dict[str, bool]] = None
    emails: Optional[Dict[str, bool]] = None
    messaging: Optional[Dict[str, bool]] = None
    social_media: Optional[Dict[str, bool]] = None
    networks: Optional[Dict[str, bool]] = None
    mobile_devices: Optional[Dict[str, bool]] = None
    personal_computers: Optional[Dict[str, bool]] = None
    smart_home: Optional[Dict[str, bool]] = None
    personal_finance: Optional[Dict[str, bool]] = None
    human_aspect: Optional[Dict[str, bool]] = None
    physical_security: Optional[Dict[str, bool]] = None
