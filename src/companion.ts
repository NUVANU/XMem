#!/usr/bin/env node
/** Dedicated private-package launcher. It never falls back to the full profile. */
import { createMcpServer } from './mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
if(process.argv.length!==2){process.stderr.write('INVALID_COMPANION_ARGUMENTS\n');process.exitCode=1;}
else createMcpServer('companion').connect(new StdioServerTransport()).catch(()=>{process.stderr.write('MCP_START_FAILED\n');process.exitCode=1;});
