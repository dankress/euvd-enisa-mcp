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

```bash
npm install
```

### Running the Server

```bash
npm run start
```

This will start the MCP server.

### Running Tests

```bash
npm run test
```

Runs the test suite using Vitest.

## Usage

The MCP server exposes various tools to query vulnerability data, including:

- Retrieving the latest vulnerabilities
- Searching vulnerabilities by score, date, product, vendor, etc.
- Getting detailed information by vulnerability ID
- Accessing advisories by ID

Refer to the source code in `src/` for detailed usage and API endpoints.

## Contributing

Contributions are welcome. Please open issues or pull requests for bug fixes, features, or improvements.

## License

This project is licensed under the terms of the MIT License. See the [LICENSE](LICENSE) file for details.