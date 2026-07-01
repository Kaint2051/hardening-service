from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

MATURITY_LEVELS = ("draft", "reviewed", "production")


class ControlCreate(BaseModel):
    title: str
    description: str = ""
    category: str


class ControlOut(BaseModel):
    id: str
    title: str
    description: str
    category: str
    maturity: str
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ControlMaturityUpdate(BaseModel):
    maturity: str = Field(..., description=f"1 trong {MATURITY_LEVELS}")


class StandardMappingCreate(BaseModel):
    standard: str
    standard_version: str
    section_id: str
    reference_url: Optional[str] = None


class StandardMappingOut(StandardMappingCreate):
    id: int
    control_id: str

    class Config:
        from_attributes = True


class RemediationVariantCreate(BaseModel):
    os_family: str
    os_version: Optional[str] = None
    check_method: str
    remediation_ref: str
    rollback_available: bool = False


class RemediationVariantOut(RemediationVariantCreate):
    id: int
    control_id: str

    class Config:
        from_attributes = True


class ControlDetailOut(ControlOut):
    standard_mappings: list[StandardMappingOut] = []
    remediation_variants: list[RemediationVariantOut] = []
