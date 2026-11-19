"""Bounded tool inputs. Inventory values never become URLs or commands."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator


class InventoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    asset_id: str = Field(min_length=1, max_length=80)
    manufacturer: str = Field(min_length=1, max_length=120)
    product: str = Field(min_length=1, max_length=160)
    version: str | None = Field(default=None, max_length=80)

    @field_validator("asset_id", "manufacturer", "product", "version")
    @classmethod
    def plain_text(cls, value: str | None) -> str | None:
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Control characters are not allowed.")
        return value


Inventory = Annotated[list[InventoryItem], Field(min_length=1, max_length=20)]
AdvisoryId = Annotated[str, Field(pattern=r"^ICSA-\d{2}-\d{3}-\d{2}$")]
AdvisoryIds = Annotated[list[AdvisoryId], Field(min_length=1, max_length=12)]


def validate_inventory(items: list[InventoryItem]) -> list[dict]:
    ids = [item.asset_id for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError("Each asset_id must be unique so every row can be accounted for.")
    vendors = {item.manufacturer.casefold() for item in items}
    if len(vendors) > 4:
        raise ValueError("This prototype accepts at most four manufacturers per call.")
    return [item.model_dump() for item in items]
