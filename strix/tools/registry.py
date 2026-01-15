import inspect
import json
import logging
import os
from collections.abc import Callable
from functools import wraps
from inspect import signature
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from strix.tools.schema import ToolDefinition, ToolSchema
from strix.utils.resource_paths import get_strix_resource_path


tools: list[dict[str, Any]] = []
_tools_by_name: dict[str, Callable[..., Any]] = {}
_tool_param_schemas: dict[str, dict[str, Any]] = {}
logger = logging.getLogger(__name__)


class ImplementedInClientSideOnlyError(Exception):
    def __init__(
        self,
        message: str = "This tool is implemented in the client side only",
    ) -> None:
        self.message = message
        super().__init__(self.message)


def _process_dynamic_content(content: str) -> str:
    if "{{DYNAMIC_SKILLS_DESCRIPTION}}" in content:
        try:
            from strix.skills import generate_skills_description

            skills_description = generate_skills_description()
            content = content.replace("{{DYNAMIC_SKILLS_DESCRIPTION}}", skills_description)
        except ImportError:
            logger.warning("Could not import skills utilities for dynamic schema generation")
            content = content.replace(
                "{{DYNAMIC_SKILLS_DESCRIPTION}}",
                "List of skills to load for this agent (max 5). Skill discovery failed.",
            )

    return content


def _load_json_schema(path: Path, validate: bool = True) -> dict[str, dict[str, Any]] | None:
    if not path.exists():
        return None
    try:
        content = path.read_text()
        content = _process_dynamic_content(content)
        schema_data: dict[str, Any] = json.loads(content)

        tools_list: list[dict[str, Any]] = []

        # Validate with Pydantic if requested
        if validate:
            try:
                validated_schema = ToolSchema.model_validate(schema_data)
                tools_list = [tool.model_dump(exclude_none=True) for tool in validated_schema.tools]
            except ValidationError as e:
                logger.warning(f"Schema validation failed for {path}: {e}")
                # Fall back to raw data if validation fails
                raw_tools = schema_data.get("tools", [])
                if isinstance(raw_tools, list):
                    tools_list = cast(list[dict[str, Any]], raw_tools)
        else:
            raw_tools = schema_data.get("tools", [])
            if isinstance(raw_tools, list):
                tools_list = cast(list[dict[str, Any]], raw_tools)

        tools_dict: dict[str, dict[str, Any]] = {}
        for tool in tools_list:
            tool_name = tool.get("name")
            if tool_name and isinstance(tool_name, str):
                tools_dict[tool_name] = tool

        return tools_dict
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning(f"Error loading schema file {path}: {e}")
        return None


def _parse_param_schema(tool_json: dict[str, Any] | None) -> dict[str, Any]:
    params: set[str] = set()
    required: set[str] = set()

    if not tool_json:
        return {"params": set(), "required": set(), "has_params": False}

    raw_parameters = tool_json.get("parameters", [])
    if not isinstance(raw_parameters, list):
        return {"params": set(), "required": set(), "has_params": False}

    parameters = cast(list[dict[str, Any]], raw_parameters)
    for param in parameters:
        name = param.get("name")
        if not name or not isinstance(name, str):
            continue
        params.add(name)
        if param.get("required", False) is True:
            required.add(name)

    return {"params": params, "required": required, "has_params": bool(params or required)}


def _get_module_name(func: Callable[..., Any]) -> str:
    module = inspect.getmodule(func)
    if not module:
        return "unknown"

    module_name = module.__name__
    if ".tools." in module_name:
        parts = module_name.split(".tools.")[-1].split(".")
        if len(parts) >= 1:
            return parts[0]
    return "unknown"


def _get_schema_path(func: Callable[..., Any]) -> Path | None:
    module = inspect.getmodule(func)
    if not module or not module.__name__:
        return None

    module_name = module.__name__

    if ".tools." not in module_name:
        return None

    parts = module_name.split(".tools.")[-1].split(".")
    if len(parts) < 2:
        return None

    folder = parts[0]
    file_stem = parts[1]
    schema_file = f"{file_stem}_schema.json"

    return get_strix_resource_path("tools", folder, schema_file)


def register_tool(
    func: Callable[..., Any] | None = None, *, sandbox_execution: bool = True
) -> Callable[..., Any]:
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        func_dict: dict[str, Any] = {
            "name": f.__name__,
            "function": f,
            "module": _get_module_name(f),
            "sandbox_execution": sandbox_execution,
        }

        sandbox_mode = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"
        if not sandbox_mode:
            try:
                schema_path = _get_schema_path(f)
                json_tools = _load_json_schema(schema_path) if schema_path else None

                if json_tools is not None and f.__name__ in json_tools:
                    func_dict["json_schema"] = json_tools[f.__name__]
                else:
                    func_dict["json_schema"] = {
                        "name": f.__name__,
                        "description": "Schema not found for tool.",
                    }
            except (TypeError, FileNotFoundError) as e:
                logger.warning(f"Error loading schema for {f.__name__}: {e}")
                func_dict["json_schema"] = {
                    "name": f.__name__,
                    "description": "Error loading schema.",
                }

        if not sandbox_mode:
            raw_json_schema = func_dict.get("json_schema")
            json_schema: dict[str, Any] | None = None
            if isinstance(raw_json_schema, dict):
                json_schema = cast(dict[str, Any], raw_json_schema)
            param_schema = _parse_param_schema(json_schema)
            _tool_param_schemas[str(func_dict["name"])] = param_schema

        tools.append(func_dict)
        _tools_by_name[str(func_dict["name"])] = f

        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return f(*args, **kwargs)

        return wrapper

    if func is None:
        return decorator
    return decorator(func)


def get_tool_by_name(name: str) -> Callable[..., Any] | None:
    return _tools_by_name.get(name)


def get_tool_names() -> list[str]:
    return list(_tools_by_name.keys())


def get_tool_param_schema(name: str) -> dict[str, Any] | None:
    return _tool_param_schemas.get(name)


def needs_agent_state(tool_name: str) -> bool:
    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        return False
    sig = signature(tool_func)
    return "agent_state" in sig.parameters


def should_execute_in_sandbox(tool_name: str) -> bool:
    for tool in tools:
        if tool.get("name") == tool_name:
            return bool(tool.get("sandbox_execution", True))
    return True


def get_tools_prompt() -> str:
    tools_by_module: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        module = tool.get("module", "unknown")
        if module not in tools_by_module:
            tools_by_module[module] = []

        json_schema = tool.get("json_schema", {})
        if json_schema:
            tools_by_module[module].append(json_schema)

    return json.dumps(tools_by_module, indent=2)


def validate_tool_schema(tool_data: dict[str, Any]) -> ToolDefinition:
    """Validate a single tool definition against the schema."""
    return ToolDefinition.model_validate(tool_data)


def validate_schema_file(path: Path) -> ToolSchema:
    """Validate a complete schema file against the Pydantic models."""
    content = path.read_text()
    content = _process_dynamic_content(content)
    schema_data = json.loads(content)
    return ToolSchema.model_validate(schema_data)


def clear_registry() -> None:
    tools.clear()
    _tools_by_name.clear()
    _tool_param_schemas.clear()
