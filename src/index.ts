#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { server } from "./server.js";

const transport = new StdioServerTransport();
try {
  await server.connect(transport);
  console.error('EUVD ENISA MCP server running on stdio');
} catch (e) {
  console.error('EUVD ENISA MCP server failed to start', e);
  process.exit(1);
}