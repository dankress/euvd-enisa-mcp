# EUVD ENISA MCP

This project provides an MCP (Model Context Protocol) server implementation related to EUVD (European Vulnerability Database) and ENISA (European Union Agency for Cybersecurity) data.

## Overview

The MCP server offers tools to query and retrieve vulnerability data, advisories, and related security information. It is designed to facilitate integration with security tools and services by providing structured access to vulnerability information.

## Project Structure

- `src/` - Source code directory containing the main server and related modules.
- `.github/workflows/ci.yml` - GitHub Actions workflow for continuous integration.
- `package.json` - Project manifest with dependencies and scripts.
- `tsconfig.json` - TypeScript configuration.
- `vitest.config.ts` - Configuration for Vitest testing framework.
- `.eslintrc.cjs` - ESLint configuration.
- `LICENSE` - Project license.

## Getting Started

### Prerequisites

- Node.js (version 16 or higher recommended)
- npm or yarn package manager

### Installation

You can use the EUVD ENISA MCP server in two ways:

#### Option 1: Direct npx execution (recommended)

The easiest way to use the EUVD ENISA MCP server is with npx:

```bash
npx -y euvd-enisa-mcp
```

This will download and run the server without requiring installation.

#### Option 2: Global installation

```bash
npm install -g euvd-enisa-mcp
euvd-enisa-mcp
```

### MCP Client Configuration

To configure an MCP client to use this server, add the following to your MCP configuration:

```json
"mcp": {
  "servers": {
    "euvd-enisa-mcp": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "euvd-enisa-mcp"]
    }
  }
}
```

This configuration allows MCP clients to automatically start and communicate with the EUVD ENISA MCP server.

### Running Tests

```bash
npm run test
```

Runs the test suite using Vitest.

## Usage

The MCP server exposes various tools to query vulnerability data from the EUVD API. These tools can be used by MCP clients to access vulnerability information.

### Available Tools

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `get_last_vulnerabilities` | Retrieves the latest vulnerabilities | None |
| `get_exploited_vulnerabilities` | Retrieves vulnerabilities that are being actively exploited | None |
| `get_critical_vulnerabilities` | Retrieves vulnerabilities with critical severity | None |
| `search_vulnerabilities` | Searches for vulnerabilities based on various criteria | `fromScore`, `toScore`, `fromEpss`, `toEpss`, `fromDate`, `toDate`, `product`, `vendor`, `assigner`, `exploited`, `page`, `text`, `size` |
| `get_euvd_by_id` | Gets detailed information about a vulnerability by its EUVD ID | `id` (required) |
| `get_advisory_by_id` | Gets an advisory by its ID | `id` (required) |

### Example Usage with an MCP Client

```javascript
// Example of using the EUVD ENISA MCP server with an MCP client
const result = await mcpClient.useTool("euvd-enisa-mcp", "search_vulnerabilities", {
  fromScore: 7.0,
  toScore: 10.0,
  product: "windows",
  vendor: "microsoft"
});

console.log(result);

For more detailed information about the API endpoints and response formats, refer to the [EUVD API documentation](https://euvdservices.enisa.europa.eu/api).

## Contributing

Contributions are welcome. Please open issues or pull requests for bug fixes, features, or improvements.

## License

This project is licensed under the terms of the MIT License. See the [LICENSE](LICENSE) file for details.
