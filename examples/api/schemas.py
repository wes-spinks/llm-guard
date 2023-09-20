from typing import Dict, Optional

from pydantic import BaseModel


class AnalyzePromptRequest(BaseModel):
    prompt: str


class AnalyzePromptResponse(BaseModel):
    sanitized_prompt: str
    is_valid: bool
    scanners: Dict[str, float]
    is_cached: Optional[bool] = False


class AnalyzeOutputRequest(BaseModel):
    prompt: str
    output: str


class AnalyzeOutputResponse(BaseModel):
    sanitized_output: str
    is_valid: bool
    scanners: Dict[str, float]
