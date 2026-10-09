import json
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, SecretStr, field_validator


class AwsAssessmentRequest(BaseModel):
    provider: Literal["aws"]
    access_key_id: str = Field(min_length=16, max_length=128)
    secret_access_key: SecretStr = Field(min_length=1, max_length=4096)
    session_token: SecretStr | None = Field(default=None, max_length=65536)


class AzureAssessmentRequest(BaseModel):
    provider: Literal["azure"]
    tenant_id: str = Field(min_length=1, max_length=128)
    client_id: str = Field(min_length=1, max_length=128)
    client_secret: SecretStr = Field(min_length=1, max_length=4096)
    subscription_ids: list[str] = Field(min_length=1, max_length=20)

    @field_validator("subscription_ids")
    @classmethod
    def validate_subscription_ids(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if any(not value or len(value) > 128 for value in normalized):
            raise ValueError("Subscription IDs must be non-empty and at most 128 characters.")
        return normalized


class GcpAssessmentRequest(BaseModel):
    provider: Literal["gcp"]
    service_account_json: SecretStr = Field(max_length=65536)
    project_ids: list[str] = Field(min_length=1, max_length=20)

    @field_validator("service_account_json")
    @classmethod
    def validate_service_account_json(cls, value: SecretStr) -> SecretStr:
        try:
            credentials = json.loads(value.get_secret_value())
        except json.JSONDecodeError as error:
            raise ValueError("Service account credentials must be valid JSON.") from error
        if not isinstance(credentials, dict) or credentials.get("type") != "service_account":
            raise ValueError("Provide a Google Cloud service account JSON key.")
        return value

    @field_validator("project_ids")
    @classmethod
    def validate_project_ids(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if any(not value or len(value) > 128 for value in normalized):
            raise ValueError("Project IDs must be non-empty and at most 128 characters.")
        return normalized


CloudAssessmentRequest = Annotated[
    Union[AwsAssessmentRequest, AzureAssessmentRequest, GcpAssessmentRequest],
    Field(discriminator="provider"),
]
