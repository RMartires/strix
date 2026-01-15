"""Pydantic models for tool schema validation."""

from typing import Any

from pydantic import BaseModel, Field


class ToolExample(BaseModel):
    """Example usage of a tool."""

    description: str | None = Field(default=None, description="Description of what this example demonstrates")
    params: dict[str, Any] = Field(default_factory=dict, description="Parameter values for this example")


class ToolParameter(BaseModel):
    """Definition of a tool parameter."""

    name: str = Field(description="Name of the parameter")
    type: str = Field(description="Type of the parameter (string, integer, boolean, dict, list, number)")
    required: bool = Field(default=False, description="Whether this parameter is required")
    description: str = Field(default="", description="Description of the parameter")


class ToolReturns(BaseModel):
    """Definition of tool return value."""

    type: str = Field(description="Type of the return value")
    description: str = Field(default="", description="Description of the return value")


class ToolDefinition(BaseModel):
    """Complete definition of a tool."""

    name: str = Field(description="Name of the tool")
    description: str = Field(description="Description of what the tool does")
    details: str | None = Field(default=None, description="Additional detailed information about the tool")
    parameters: list[ToolParameter] = Field(default_factory=list, description="List of tool parameters")
    returns: ToolReturns | None = Field(default=None, description="Return value specification")
    notes: str | None = Field(default=None, description="Important usage notes")
    examples: list[ToolExample] | None = Field(default=None, description="Usage examples")


class ToolSchema(BaseModel):
    """Root schema for a tool definition file."""

    important: str | None = Field(default=None, description="Important notice for this tool category")
    tools: list[ToolDefinition] = Field(description="List of tool definitions")

