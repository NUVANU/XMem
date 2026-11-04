#!/usr/bin/env node
/** Explicit opt-in: nine Companion plus six bound engineering tools, no admin fallback. */
import { createMcpServer } from './mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
if(process.argv.length!==2){process.stderr.write('INVALID_ENGINEERING_COMPANION_ARGUMENTS\n');process.exitCode=1;}
else createMcpServer('engineering').connect(new StdioServerTransport()).catch(()=>{process.stderr.write('MCP_START_FAILED\n');process.exitCode=1;});
