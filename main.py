import base64
import binascii
import logging
import os
import re
import subprocess
import tempfile

from mcp.server.mcpserver import MCPServer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create MCP server instance
mcp = MCPServer("ClamAV Scanner")


def _env_int(name, default):
    """Read a positive integer from the environment, falling back to default."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid %s value %r; using default %d", name, raw, default)
        return default
    if value <= 0:
        logger.warning("Non-positive %s value %d; using default %d", name, value, default)
        return default
    return value


# Limits (overridable via env)
MAX_B64_LEN = _env_int("MAX_B64_LEN", 28 * 1024 * 1024)  # ~20 MB decoded, in base64 chars
SCAN_TIMEOUT = _env_int("SCAN_TIMEOUT", 120)  # seconds
# Output cap in characters (not bytes); legacy MAX_OUTPUT_BYTES still honored.
MAX_OUTPUT_CHARS = _env_int("MAX_OUTPUT_CHARS", _env_int("MAX_OUTPUT_BYTES", 4096))


def _sanitize_filename(filename: str) -> str:
    """Return a safe basename; raise ValueError if the name is unusable."""
    if not isinstance(filename, str):
        raise ValueError("filename must be a string")
    name = os.path.basename(filename.replace("\\", "/")).strip()
    if not name or name in (".", ".."):
        raise ValueError("invalid filename")
    # Reject path separators, control chars, newlines
    if re.search(r"[/\\\x00-\x1f\x7f]", name):
        raise ValueError("invalid filename")
    if name.startswith("."):
        raise ValueError("invalid filename")
    return name[:255]


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} chars omitted]"


@mcp.tool()
def scan_file(base64_data: str, filename: str) -> dict:
    """
    Scan a base64-encoded file using ClamAV.

    Args:
        base64_data (str): Base64 encoded string representing a file
        filename (str): Name of the file to use in the scan

    Returns:
        dict: Scan results including truncated clamscan output
    """
    try:
        safe_name = _sanitize_filename(filename)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    logger.info(f"Received scan request for file: {safe_name}")

    if not isinstance(base64_data, str) or len(base64_data) > MAX_B64_LEN:
        return {"success": False, "error": "input too large or invalid"}

    temp_file_path = None
    try:
        try:
            file_content = base64.b64decode(base64_data, validate=True)
        except (binascii.Error, ValueError):
            return {"success": False, "error": "invalid base64 input"}

        with tempfile.NamedTemporaryFile(delete=False, mode="wb", suffix=f"_{safe_name}") as temp_file:
            temp_file.write(file_content)
            temp_file_path = temp_file.name
        # Permissions remain 0600 (default); do NOT widen them.

        logger.info(f"Created temporary file: {temp_file_path}")

        try:
            result = subprocess.run(
                ["clamscan", temp_file_path],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT,
            )
            output = result.stdout + result.stderr
            logger.info("Scan completed successfully")
            return {
                "success": True,
                "result": _truncate(output, MAX_OUTPUT_CHARS),
            }
        except subprocess.TimeoutExpired:
            logger.error("clamscan timed out")
            return {"success": False, "error": "scan timed out"}
        except FileNotFoundError:
            logger.error("clamscan not found")
            return {"success": False, "error": "scanner unavailable"}

    except Exception as e:
        logger.error(f"Error during scan: {e}")
        return {"success": False, "error": "scan failed"}
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
                logger.info(f"Cleaned up temporary file: {temp_file_path}")
            except Exception as cleanup_err:
                logger.error(f"Failed to clean up temp file {temp_file_path}: {cleanup_err}")


if __name__ == "__main__":
    mcp.run(transport="sse")
