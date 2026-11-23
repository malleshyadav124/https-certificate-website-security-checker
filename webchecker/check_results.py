"""Shared result status and message types for independent security checks."""

from dataclasses import dataclass
from enum import Enum


class CheckStatus(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    NOT_CHECKED = "NOT_CHECKED"


@dataclass(frozen=True)
class CheckResult:
    status: CheckStatus
    message: str
