import sys
import signal
import inspect
import logging
import argparse
import importlib
from pathlib import Path
from typing import Annotated, Optional
import typing_inspection.introspection as intro

from mcp.server.fastmcp import FastMCP

# ida/idapro must go first to initialize idalib
# IDA 9.0+ uses 'ida' module, IDA 8.x uses 'idapro'
try:
    import ida as idapro  # IDA 9.0+
except ImportError:
    import idapro  # IDA 8.x

import ida_auto
import ida_hexrays

logger = logging.getLogger(__name__)

mcp = FastMCP("github.com/icryo/ida-pro-mcp#idalib")

# Global state for database management
_db_state = {
    "loaded": False,
    "path": None,
    "tools_registered": False,
    "unsafe_mode": False,
}

def _wrap_with_db_check(func):
    """Wrap a function to check if database is loaded before calling"""
    import functools

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not _db_state["loaded"]:
            raise RuntimeError("No database is currently loaded. Use load_database tool first.")
        return func(*args, **kwargs)

    return wrapper

def _register_ida_tools():
    """Register IDA tools from mcp-plugin.py after database is loaded"""
    if _db_state["tools_registered"]:
        logger.debug("IDA tools already registered")
        return

    plugin = importlib.import_module("ida_pro_mcp.mcp-plugin")
    logger.debug("adding IDA tools...")
    for name, callable in plugin.rpc_registry.methods.items():
        if _db_state["unsafe_mode"] or name not in plugin.rpc_registry.unsafe:
            logger.debug("adding tool: %s: %s", name, callable)
            # Wrap the callable to check database state
            wrapped = _wrap_with_db_check(callable)
            mcp.add_tool(wrapped, name)

    _db_state["tools_registered"] = True
    fixup_tool_argument_descriptions(mcp)
    logger.info("IDA tools registered successfully")

@mcp.tool()
def load_database(
    path: Annotated[str, "Path to the binary file or IDB to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis after loading (default: True)"] = True
) -> dict:
    """Load a new binary file or IDB database for analysis. Closes any currently open database first."""
    global _db_state

    input_path = Path(path)
    if not input_path.exists():
        return {"success": False, "error": f"File not found: {path}"}

    # Close existing database if one is open
    if _db_state["loaded"]:
        logger.info("Closing current database: %s", _db_state["path"])
        idapro.close_database()
        _db_state["loaded"] = False
        _db_state["path"] = None

    # Open new database
    logger.info("Opening database: %s", input_path)
    if idapro.open_database(str(input_path), run_auto_analysis=run_auto_analysis):
        return {"success": False, "error": f"Failed to open database: {path}"}

    if run_auto_analysis:
        logger.debug("Waiting for auto-analysis to complete...")
        ida_auto.auto_wait()

    # Initialize Hex-Rays if not already done
    if not ida_hexrays.init_hexrays_plugin():
        logger.warning("Failed to initialize Hex-Rays decompiler - decompilation will not be available")

    _db_state["loaded"] = True
    _db_state["path"] = str(input_path.absolute())

    # Register IDA tools on first database load
    _register_ida_tools()

    return {
        "success": True,
        "path": _db_state["path"],
        "message": f"Successfully loaded {input_path.name}"
    }

@mcp.tool()
def close_database() -> dict:
    """Close the currently open database."""
    global _db_state

    if not _db_state["loaded"]:
        return {"success": False, "error": "No database is currently open"}

    logger.info("Closing database: %s", _db_state["path"])
    idapro.close_database()

    old_path = _db_state["path"]
    _db_state["loaded"] = False
    _db_state["path"] = None

    return {
        "success": True,
        "message": f"Successfully closed database: {old_path}"
    }

@mcp.tool()
def save_database(
    path: Annotated[Optional[str], "Optional path to save the database to. If not provided, saves to the current IDB path."] = None
) -> dict:
    """
    Save the current database to disk. This preserves all analysis including:
    - Function names and boundaries
    - Type definitions and assignments
    - Comments (all types)
    - Structures and enums
    - Cross-references
    - Everything else in the IDB

    If no path is provided, saves to the original location (creating .idb/.i64 file).
    If a path is provided, saves to that location (useful for creating backups or snapshots).
    """
    global _db_state

    if not _db_state["loaded"]:
        return {"success": False, "error": "No database is currently open"}

    import idc

    if path:
        save_path = Path(path)
        # Ensure it has proper extension
        if save_path.suffix not in [".idb", ".i64"]:
            # Add appropriate extension based on bitness
            import ida_ida
            if ida_ida.inf_is_64bit():
                save_path = save_path.with_suffix(".i64")
            else:
                save_path = save_path.with_suffix(".idb")

        logger.info("Saving database to: %s", save_path)
        # Use idc.save_database with explicit path
        success = idc.save_database(str(save_path), idc.DBFL_COMP)
        saved_to = str(save_path.absolute())
    else:
        logger.info("Saving database to current location")
        # Save to current location
        success = idc.save_database("", idc.DBFL_COMP)
        saved_to = _db_state["path"]

    if success:
        return {
            "success": True,
            "path": saved_to,
            "message": f"Successfully saved database to {saved_to}"
        }
    else:
        return {
            "success": False,
            "error": "Failed to save database"
        }

@mcp.tool()
def get_database_status() -> dict:
    """Get the current database status - whether a database is loaded and its path."""
    return {
        "loaded": _db_state["loaded"],
        "path": _db_state["path"],
        "tools_available": _db_state["tools_registered"]
    }

def fixup_tool_argument_descriptions(mcp: FastMCP):
    # In our tool definitions within `mcp-plugin.py`, we use `typing.Annotated` on function parameters
    # to attach documentation. For example:
    #
    #     def get_function_by_name(
    #         name: Annotated[str, "Name of the function to get"]
    #     ) -> Function:
    #         """Get a function by its name"""
    #         ...
    #
    # However, the interpretation of Annotated is left up to static analyzers and other tools.
    # FastMCP doesn't have any special handling for these comments, so we splice them into the
    # tool metadata ourselves here.
    #
    # Example, before:
    #
    #     tool.parameter={
    #       properties: {
    #         name: {
    #           title: "Name",
    #           type: "string"
    #         }
    #       },
    #       required: ["name"],
    #       title: "get_function_by_nameArguments",
    #       type: "object"
    #     }
    #
    # Example, after:
    #
    #     tool.parameter={
    #       properties: {
    #         name: {
    #           title: "Name",
    #           type: "string"
    #           description: "Name of the function to get"
    #         }
    #       },
    #       required: ["name"],
    #       title: "get_function_by_nameArguments",
    #       type: "object"
    #     }
    #
    # References:
    #   - https://docs.python.org/3/library/typing.html#typing.Annotated
    #   - https://fastapi.tiangolo.com/python-types/#type-hints-with-metadata-annotations

    # unfortunately, FastMCP.list_tools() is async, so we break with best practices and reach into `._tool_manager`
    # rather than spinning up an asyncio runtime just to fetch the (non-async) list of tools.
    for tool in mcp._tool_manager.list_tools():
        sig = inspect.signature(tool.fn)
        for name, parameter in sig.parameters.items():
            # this instance is a raw `typing._AnnotatedAlias` that we can't do anything with directly.
            # it renders like:
            #
            #      typing.Annotated[str, 'Name of the function to get']
            if not parameter.annotation:
                continue

            # this instance will look something like:
            #
            #     InspectedAnnotation(type=<class 'str'>, qualifiers=set(), metadata=['Name of the function to get'])
            #
            annotation = intro.inspect_annotation(
                                                  parameter.annotation,
                                                  annotation_source=intro.AnnotationSource.ANY
                                              )

            # for our use case, where we attach a single string annotation that is meant as documentation,
            # we extract that string and assign it to "description" in the tool metadata.

            if annotation.type is not str:
                continue

            if len(annotation.metadata) != 1:
                continue

            description = annotation.metadata[0]
            if not isinstance(description, str):
                continue

            logger.debug("adding parameter documentation %s(%s='%s')", tool.name, name, description)
            tool.parameters["properties"][name]["description"] = description

def main():
    global _db_state

    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug messages")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to listen on, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8745, help="Port to listen on, default: 8745")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)")
    parser.add_argument("input_path", type=Path, nargs="?", default=None, help="Optional path to the input file to analyze. If not provided, use load_database tool to load files.")
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        if hasattr(idapro, 'enable_console_messages'):
            idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        if hasattr(idapro, 'enable_console_messages'):
            idapro.enable_console_messages(False)

    mcp.settings.log_level = logging.getLevelName(log_level)
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    logging.basicConfig(level=log_level)

    # reset logging levels that might be initialized in idapythonrc.py
    # which is evaluated during import of idalib.
    logging.getLogger().setLevel(log_level)

    # Store unsafe mode for later tool registration
    _db_state["unsafe_mode"] = args.unsafe

    # If input_path provided, load it immediately (backwards compatible)
    if args.input_path is not None:
        if not args.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {args.input_path}")

        logger.info("opening database: %s", args.input_path)
        if idapro.open_database(str(args.input_path), run_auto_analysis=True):
            raise RuntimeError("failed to analyze input file")

        logger.debug("idalib: waiting for analysis...")
        ida_auto.auto_wait()

        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("failed to initialize Hex-Rays decompiler")

        _db_state["loaded"] = True
        _db_state["path"] = str(args.input_path.absolute())

        # Register IDA tools immediately since we have a database
        _register_ida_tools()
    else:
        logger.info("Starting without a database. Use load_database tool to load a binary.")

    # Setup signal handlers to ensure IDA database is properly closed on shutdown.
    #
    # PROBLEM: When uvicorn (used by FastMCP's SSE transport) receives SIGINT/SIGTERM:
    #   1. It captures the signal and performs graceful shutdown
    #   2. After shutdown, it re-raises the signal with the default handler
    #   3. The default handler immediately terminates the process at the OS level
    #   4. This bypasses all remaining Python code (try/except/finally blocks)
    #
    # SOLUTION: Register our signal handlers BEFORE calling mcp.run(). When a signal
    # arrives, our handlers execute first, allowing us to close the IDA database
    # cleanly before the process terminates.
    def cleanup_and_exit(signum, frame):
        if _db_state["loaded"]:
            logger.info("Closing IDA database...")
            idapro.close_database()
            logger.info("IDA database closed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # NOTE: npx @modelcontextprotocol/inspector for debugging
    logger.info("MCP Server available at: http://%s:%d/sse", mcp.settings.host, mcp.settings.port)
    mcp.run(transport="sse")

if __name__ == "__main__":
    main()
