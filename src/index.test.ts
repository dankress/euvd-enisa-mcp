/// <reference types="vitest/globals" />

import { setupServer } from 'msw/node'
import { http, HttpResponse } from 'msw'
import { euvdApi, server } from './server';

vi.mock('@modelcontextprotocol/sdk/server/mcp.js', async () => {
  const McpServer = vi.fn()
  McpServer.prototype.tool = vi.fn()
  return { McpServer }
});

const restHandlers = [
  http.get('https://euvdservices.enisa.europa.eu/api/lastvulnerabilities', () => {
    return HttpResponse.json({ "foo": "bar" })
  }),
  http.get('https://euvdservices.enisa.europa.eu/api/criticalvulnerabilities', () => {
    return HttpResponse.json([
      {
        "id": "CVE-2024-40854",
        "published": "2024-07-10T14:15:11.750Z",
        "lastModified": "2024-07-10T14:15:11.750Z",
        "vulnStatus": "Awaiting Analysis",
        "descriptions": [
          {
            "lang": "en",
            "value": "In the Linux kernel, the following vulnerability has been resolved:\n\ndrm/amd/display: Fix potential null pointer dereference in dcn20_validate_bandwidth\n\n[Why]\nIn dcn20_validate_bandwidth, we have this expression:\n\n\tif (new_hw_state->stream_count) {\n\t\t...\n\t\tif (context->bw_ctx.dml.vba.ValidationStatus[context->bw_ctx.dml.vba.soc.num_states] != DML_VALIDATION_OK)\n\t\t\treturn false;\n\n`new_hw_state` gets dereferenced, but this is a stale pointer when we\nre-validate a context that's already had its streams released, for\nexample during a link loss.\n\n[How]\nMove the dereference to after `context->stream_count` is checked."
          }
        ],
        "metrics": {},
        "references": [],
        "cveTags": [],
        "timeline": []
      }
    ])
  }),
  http.get('https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities', () => {
    return HttpResponse.json([
      {
        "id": "CVE-2024-12345",
        "exploited": true,
        "published": "2024-01-15T10:30:00.000Z"
      }
    ])
  }),
  http.get('https://euvdservices.enisa.europa.eu/api/search', ({ request }) => {
    const url = new URL(request.url)
    const product = url.searchParams.get('product')
    const fromScore = url.searchParams.get('fromScore')
    
    return HttpResponse.json({
      "results": [
        {
          "id": "CVE-2024-SEARCH",
          "product": product || "test-product",
          "score": fromScore ? parseFloat(fromScore) + 1 : 7.5
        }
      ],
      "total": 1
    })
  }),
  http.get('https://euvdservices.enisa.europa.eu/api/enisaid', ({ request }) => {
    const url = new URL(request.url)
    const id = url.searchParams.get('id')
    
    return HttpResponse.json({
      "id": id,
      "title": "Test EUVD Entry",
      "description": "Mock EUVD entry for testing"
    })
  }),
  http.get('https://euvdservices.enisa.europa.eu/api/advisory', ({ request }) => {
    const url = new URL(request.url)
    const id = url.searchParams.get('id')
    
    return HttpResponse.json({
      "advisoryId": id,
      "title": "Test Advisory",
      "severity": "HIGH",
      "recommendations": ["Update to latest version"]
    })
  }),
]

const mswServer = setupServer(...restHandlers)

beforeAll(() => mswServer.listen({ onUnhandledRequest: 'error' }))

afterAll(() => mswServer.close())

afterEach(() => mswServer.resetHandlers())

describe("euvd-enisa-mcp", () => {
  describe("API endpoints", () => {
    it("get_last_vulnerabilities", async () => {
      const response = await euvdApi.get('/lastvulnerabilities');
      expect(response.data).toEqual({ "foo": "bar" });
    })

    it("get_critical_vulnerabilities", async () => {
      const response = await euvdApi.get('/criticalvulnerabilities');
      expect(response.data).toEqual([
        {
          "id": "CVE-2024-40854",
          "published": "2024-07-10T14:15:11.750Z",
          "lastModified": "2024-07-10T14:15:11.750Z",
          "vulnStatus": "Awaiting Analysis",
          "descriptions": [
            {
              "lang": "en",
              "value": "In the Linux kernel, the following vulnerability has been resolved:\n\ndrm/amd/display: Fix potential null pointer dereference in dcn20_validate_bandwidth\n\n[Why]\nIn dcn20_validate_bandwidth, we have this expression:\n\n\tif (new_hw_state->stream_count) {\n\t\t...\n\t\tif (context->bw_ctx.dml.vba.ValidationStatus[context->bw_ctx.dml.vba.soc.num_states] != DML_VALIDATION_OK)\n\t\t\treturn false;\n\n`new_hw_state` gets dereferenced, but this is a stale pointer when we\nre-validate a context that's already had its streams released, for\nexample during a link loss.\n\n[How]\nMove the dereference to after `context->stream_count` is checked."
            }
          ],
          "metrics": {},
          "references": [],
          "cveTags": [],
          "timeline": []
        }
      ]);
    })

    it("get_exploited_vulnerabilities", async () => {
      const response = await euvdApi.get('/exploitedvulnerabilities');
      expect(response.data).toEqual([
        {
          "id": "CVE-2024-12345",
          "exploited": true,
          "published": "2024-01-15T10:30:00.000Z"
        }
      ]);
    })

    it("search_vulnerabilities", async () => {
      const params = {
        product: "nginx",
        fromScore: 7.0,
        toScore: 10.0
      };
      const response = await euvdApi.get('/search', { params });
      expect(response.data).toEqual({
        "results": [
          {
            "id": "CVE-2024-SEARCH",
            "product": "nginx",
            "score": 8.0
          }
        ],
        "total": 1
      });
    })

    it("get_euvd_by_id", async () => {
      const testId = "EUVD-2024-001";
      const response = await euvdApi.get('/enisaid', { params: { id: testId } });
      expect(response.data).toEqual({
        "id": testId,
        "title": "Test EUVD Entry",
        "description": "Mock EUVD entry for testing"
      });
    })

    it("get_advisory_by_id", async () => {
      const testId = "ADV-2024-001";
      const response = await euvdApi.get('/advisory', { params: { id: testId } });
      expect(response.data).toEqual({
        "advisoryId": testId,
        "title": "Test Advisory",
        "severity": "HIGH",
        "recommendations": ["Update to latest version"]
      });
    })
  })

  describe("MCP Server", () => {
    it("should be properly initialized", () => {
      expect(server).toBeDefined();
      // Since we're mocking McpServer, verify the mock was called with correct parameters
      const MockedMcpServer = vi.mocked(server.constructor);
      expect(MockedMcpServer).toHaveBeenCalledWith({
        name: "euvd-enisa-mcp",
        version: "1.0.4"
      });
    })

    it("should have registered all tools", () => {
      // Verify that the server.tool method was called for each tool
      const toolCalls = vi.mocked(server.tool).mock.calls;
      
      expect(toolCalls.length).toBe(6);
      
      const toolNames = toolCalls.map(call => call[0]);
      expect(toolNames).toContain("get_last_vulnerabilities");
      expect(toolNames).toContain("get_exploited_vulnerabilities");
      expect(toolNames).toContain("get_critical_vulnerabilities");
      expect(toolNames).toContain("search_vulnerabilities");
      expect(toolNames).toContain("get_euvd_by_id");
      expect(toolNames).toContain("get_advisory_by_id");
    })

    it("should have proper tool configurations", () => {
      const toolCalls = vi.mocked(server.tool).mock.calls;
      
      // Check that tools without parameters have empty schema
      const simpleTools = ["get_last_vulnerabilities", "get_exploited_vulnerabilities", "get_critical_vulnerabilities"];
      simpleTools.forEach(toolName => {
        const toolCall = toolCalls.find(call => call[0] === toolName);
        expect(toolCall).toBeDefined();
        expect(toolCall![1]).toEqual({}); // Empty schema
      });

      // Check that search_vulnerabilities has proper schema
      const searchToolCall = toolCalls.find(call => call[0] === "search_vulnerabilities");
      expect(searchToolCall).toBeDefined();
      expect(searchToolCall![1]).toHaveProperty('fromScore');
      expect(searchToolCall![1]).toHaveProperty('toScore');
      expect(searchToolCall![1]).toHaveProperty('product');

      // Check that ID-based tools have id parameter
      const idTools = ["get_euvd_by_id", "get_advisory_by_id"];
      idTools.forEach(toolName => {
        const toolCall = toolCalls.find(call => call[0] === toolName);
        expect(toolCall).toBeDefined();
        expect(toolCall![1]).toHaveProperty('id');
      });
    })
  })
})