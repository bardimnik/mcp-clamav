# ClamAV MCP

Simple ClamAV MCP that allows scanning files for viruses using the ClamAV engine.

![Cursor ClamAV Integration](image.png)

## Requirements

This project requires ClamAV to be installed on your system. Here's how to install it:

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install clamav clamav-daemon
```

### Windows
1. Download the ClamAV installer from [ClamAV's official website](https://www.clamav.net/downloads)
2. Run the installer and follow the setup wizard
3. Make sure to add ClamAV to your system PATH

### macOS
```bash
brew install clamav
```

## Security

**This server has no authentication and no TLS. Do not expose it to an untrusted network.**
Run it on localhost or behind a reverse proxy with authentication and TLS. Anyone who can reach the SSE endpoint can ask the server to scan arbitrary files with ClamAV and read the output.

## Usage

Run the MCP server directly (SSE transport, listens on 127.0.0.1:8000 by default):

```bash
uv run python main.py
```

Or via the MCP CLI:

```bash
uv run mcp run main.py -t sse
```

The server listens for SSE connections on port 8000 by default.

## Environment variables

- `MAX_B64_LEN` (default `29360128`, ~20 MB decoded) — max accepted base64 input length in characters.
- `SCAN_TIMEOUT` (default `120`) — max seconds for a single clamscan run before the scan is aborted.
- `MAX_OUTPUT_CHARS` (default `4096`) — max characters of clamscan output returned to the client; longer output is truncated. (`MAX_OUTPUT_BYTES` is still honored as a legacy fallback.)

## Cursor Configuration

To use this MCP with Cursor, add the following configuration to your Cursor settings:

```json
{
  "mcpServers": {
    "ClamAV Server": {
      "url": "http://127.0.0.1:8000/sse"
    }
  }
}
```

This configuration tells Cursor to connect to the ClamAV MCP server. Do not expose the endpoint directly; put it behind a reverse proxy with authentication and TLS, or keep it on localhost.

## API

The MCP provides a single endpoint:

### scan_file
- Parameters:
  - `base64_data`: Base64 encoded string of the file to scan
  - `filename`: Name of the file to use in the scan
- Returns:
  - `success`: Boolean indicating if the scan was successful
  - `result`: Raw output from clamscan command
  - `error`: Error message if the scan failed 