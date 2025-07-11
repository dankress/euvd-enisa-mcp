import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from 'axios';

export const server = new McpServer({
  name: "euvd-enisa-mcp",
  version: "1.0.6"
});

export const euvdApi = axios.create({
  baseURL: 'https://euvdservices.enisa.europa.eu/api',
});

server.tool(
  "get_last_vulnerabilities",
  {
    description: "Retrieves the latest vulnerabilities"
  },
  async () => {
    try {
      const response = await euvdApi.get('/lastvulnerabilities');
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          content: [
            {
              type: "text",
              text: `EUVD API error: ${
                error.response?.data.message ?? error.message
              }`,
            },
          ],
          isError: true,
        };
      }
      throw error;
    }
  }
);

server.tool(
  "get_exploited_vulnerabilities",
  {
    description: "Retrieves vulnerabilities that are being actively exploited"
  },
  async () => {
    try {
      const response = await euvdApi.get('/exploitedvulnerabilities');
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          content: [
            {
              type: "text",
              text: `EUVD API error: ${
                error.response?.data.message ?? error.message
              }`,
            },
          ],
          isError: true,
        };
      }
      throw error;
    }
  }
);

server.tool(
  "get_critical_vulnerabilities",
  {
    description: "Retrieves vulnerabilities with critical severity"
  },
  async () => {
    try {
      const response = await euvdApi.get('/criticalvulnerabilities');
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          content: [
            {
              type: "text",
              text: `EUVD API error: ${
                error.response?.data.message ?? error.message
              }`,
            },
          ],
          isError: true,
        };
      }
      throw error;
    }
  }
);

server.tool(
  "search_vulnerabilities",
  {
    description: "Searches for vulnerabilities based on various criteria",
    fromScore: z.number().min(0).max(10).optional(),
    toScore: z.number().min(0).max(10).optional(),
    fromEpss: z.number().min(0).max(100).optional(),
    toEpss: z.number().min(0).max(100).optional(),
    fromDate: z.string().optional(),
    toDate: z.string().optional(),
    product: z.string().optional(),
    vendor: z.string().optional(),
    assigner: z.string().optional(),
    exploited: z.boolean().optional(),
    page: z.number().optional(),
    text: z.string().optional(),
    size: z.number().optional(),
  },
  async (params) => {
    try {
      const response = await euvdApi.get('/search', { params });
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          content: [
            {
              type: "text",
              text: `EUVD API error: ${
                error.response?.data.message ?? error.message
              }`,
            },
          ],
          isError: true,
        };
      }
      throw error;
    }
  }
);

server.tool(
  "get_euvd_by_id",
  {
    description: "Gets detailed information about a vulnerability by its EUVD ID",
    id: z.string(),
  },
  async ({ id }) => {
    try {
      const response = await euvdApi.get('/enisaid', { params: { id } });
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          content: [
            {
              type: "text",
              text: `EUVD API error: ${
                error.response?.data.message ?? error.message
              }`,
            },
          ],
          isError: true,
        };
      }
      throw error;
    }
  }
);

server.tool(
  "get_advisory_by_id",
  {
    description: "Gets an advisory by its ID",
    id: z.string(),
  },
  async ({ id }) => {
    try {
      const response = await euvdApi.get('/advisory', { params: { id } });
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          content: [
            {
              type: "text",
              text: `EUVD API error: ${
                error.response?.data.message ?? error.message
              }`,
            },
          ],
          isError: true,
        };
      }
      throw error;
    }
  }
);