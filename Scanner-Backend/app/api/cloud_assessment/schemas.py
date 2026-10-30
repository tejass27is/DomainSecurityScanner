import json
import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


class CloudAssessmentBaseRequest(BaseModel):
    client_name: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("client_name")
    @classmethod
    def normalize_client_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Enter the client name.")
        return normalized


class AwsAssessmentRequest(CloudAssessmentBaseRequest):
    provider: Literal["aws"]
    access_key_id: str = Field(min_length=16, max_length=128)
    secret_access_key: SecretStr = Field(min_length=1, max_length=4096)
    session_token: SecretStr | None = Field(default=None, max_length=65536)
    aws_region: str | None = Field(default=None, max_length=32)
    aws_regions: list[str] | None = Field(default=None, min_length=1, max_length=50)

    @field_validator("aws_region")
    @classmethod
    def validate_aws_region(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d", normalized):
            raise ValueError("Enter a valid AWS region, such as us-east-1.")
        return normalized

    @field_validator("aws_regions")
    @classmethod
    def validate_aws_regions(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        normalized = [value.strip().lower() for value in values]
        if any(
            not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d", region)
            for region in normalized
        ):
            raise ValueError("Enter valid AWS regions, such as us-east-1.")
        if len(set(normalized)) != len(normalized):
            raise ValueError("Select each AWS region only once.")
        return normalized

    @model_validator(mode="after")
    def validate_aws_region_selection(self) -> "AwsAssessmentRequest":
        if self.aws_region and self.aws_regions is not None:
            raise ValueError("Use either aws_region or aws_regions, not both.")
        return self


class AzureAssessmentRequest(CloudAssessmentBaseRequest):
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


class GcpAssessmentRequest(CloudAssessmentBaseRequest):
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
