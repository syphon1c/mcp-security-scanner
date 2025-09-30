#!/usr/bin/env python3
"""
Mock MCP (Model Context Protocol) Server for Security Testing

This server implements a basic MCP protocol server with SIMULATED security
vulnerabilities for testing the MCP Security Scanner's remote scanning capabilities.

SAFETY: This server only simulates vulnerabilities and does NOT execute real commands,
read actual files, or perform any dangerous operations. All responses are mocked.

Safe for testing and development environments.
"""

import json
import asyncio
import logging
import argparse
import sqlite3
import os
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional
from aiohttp import web, WSMsgType
import aiohttp_cors

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MockMCPServer:
    def __init__(self, host: str = "localhost", port: int = 8000, vulnerable: bool = True):
        self.host = host
        self.port = port
        self.vulnerable = vulnerable
        self.app = web.Application()
        self.setup_database()
        self.setup_routes()
        self.setup_cors()
        
        # MCP Server Info
        self.server_info = {
            "name": "Mock MCP Server",
            "version": "1.0.0",
            "protocol": "2024-11-05",
            "capabilities": [
                "tools",
                "resources",
                "prompts",
                "sampling"
            ]
        }
        
        # Mock tools with vulnerabilities
        self.tools = [
            {
                "name": "execute_command",
                "description": "Execute system commands (VULNERABLE)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Command to execute"
                        }
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "query_database",
                "description": "Query user database (VULNERABLE TO SQL INJECTION)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "SQL query to execute"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "User ID for query"
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "read_file",
                "description": "Read file contents (VULNERABLE TO PATH TRAVERSAL)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to file to read"
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "generate_report",
                "description": "Generate HTML report (VULNERABLE TO XSS)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Report title"
                        },
                        "content": {
                            "type": "string",
                            "description": "Report content"
                        }
                    },
                    "required": ["title", "content"]
                }
            },
            {
                "name": "safe_calculator",
                "description": "Safe mathematical calculator",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "expression": {
                            "type": "string",
                            "description": "Mathematical expression to evaluate"
                        }
                    },
                    "required": ["expression"]
                }
            }
        ]
        
        # Mock resources with vulnerabilities
        self.resources = [
            {
                "uri": "file:///etc/passwd",
                "name": "System Password File",
                "description": "System password file (SHOULD BE BLOCKED)",
                "mimeType": "text/plain"
            },
            {
                "uri": "config://database",
                "name": "Database Configuration",
                "description": "Database connection details",
                "mimeType": "application/json"
            },
            {
                "uri": "memory://users",
                "name": "User Data",
                "description": "In-memory user data",
                "mimeType": "application/json"
            },
            {
                "uri": "http://evil.example.com/malicious",
                "name": "External Malicious Resource",
                "description": "External resource for testing",
                "mimeType": "text/plain"
            }
        ]

    def setup_database(self):
        """Setup SQLite database with test data"""
        self.db_path = "/tmp/mock_mcp_test.db"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                admin BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Insert test data
        test_users = [
            (1, "admin", "admin@example.com", "admin123", True),
            (2, "user1", "user1@example.com", "password123", False),
            (3, "user2", "user2@example.com", "secret456", False),
        ]
        
        cursor.execute("DELETE FROM users")
        cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", test_users)
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")

    def setup_routes(self):
        """Setup HTTP routes"""
        self.app.router.add_post('/mcp/initialize', self.handle_initialize)
        self.app.router.add_post('/mcp/tools/list', self.handle_tools_list)
        self.app.router.add_post('/mcp/tools/call', self.handle_tools_call)
        self.app.router.add_post('/mcp/resources/list', self.handle_resources_list)
        self.app.router.add_post('/mcp/resources/read', self.handle_resources_read)
        self.app.router.add_get('/health', self.handle_health)
        self.app.router.add_get('/debug/info', self.handle_debug_info)
        self.app.router.add_get('/ws', self.handle_websocket)

    def setup_cors(self):
        """Setup CORS"""
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        
        for route in list(self.app.router.routes()):
            cors.add(route)

    async def handle_initialize(self, request):
        """Handle MCP initialize request"""
        try:
            data = await request.json()
            logger.info(f"Initialize request: {data}")
            
            # Check protocol version
            client_version = data.get("params", {}).get("protocolVersion", "unknown")
            
            response = {
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": True, "listChanged": True},
                        "prompts": {"listChanged": True},
                        "sampling": {}
                    },
                    "serverInfo": self.server_info
                }
            }
            
            return web.json_response(response)
            
        except Exception as e:
            logger.error(f"Error in initialize: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "id": data.get("id") if 'data' in locals() else None,
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                }
            }, status=500)

    async def handle_tools_list(self, request):
        """Handle tools/list request"""
        try:
            data = await request.json()
            logger.info("Tools list request")
            
            response = {
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "result": {
                    "tools": self.tools
                }
            }
            
            return web.json_response(response)
            
        except Exception as e:
            logger.error(f"Error in tools list: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)}
            }, status=500)

    async def handle_tools_call(self, request):
        """Handle tools/call request with intentional vulnerabilities"""
        try:
            data = await request.json()
            params = data.get("params", {})
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            logger.info(f"Tool call: {tool_name} with args: {arguments}")
            
            if tool_name == "execute_command":
                result = await self.tool_execute_command(arguments)
            elif tool_name == "query_database":
                result = await self.tool_query_database(arguments)
            elif tool_name == "read_file":
                result = await self.tool_read_file(arguments)
            elif tool_name == "generate_report":
                result = await self.tool_generate_report(arguments)
            elif tool_name == "safe_calculator":
                result = await self.tool_safe_calculator(arguments)
            else:
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Unknown tool: {tool_name}"
                        }
                    ],
                    "isError": True
                }
            
            response = {
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "result": result
            }
            
            return web.json_response(response)
            
        except Exception as e:
            logger.error(f"Error in tools call: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)}
            }, status=500)

    async def tool_execute_command(self, arguments):
        """MOCK: Simulated command execution (SAFE - NO ACTUAL EXECUTION)"""
        command = arguments.get("command", "")
        
        if not self.vulnerable:
            return {
                "content": [{"type": "text", "text": "Command execution disabled in safe mode"}],
                "isError": False
            }
        
        # MOCK RESPONSES - NO ACTUAL COMMAND EXECUTION FOR SAFETY
        logger.info(f"MOCK: Simulating command execution for: {command}")
        
        # Generate mock responses based on common commands
        mock_responses = {
            "ls": "file1.txt\nfile2.txt\ndirectory1/\n",
            "pwd": "/home/user",
            "whoami": "mockuser",
            "id": "uid=1000(mockuser) gid=1000(mockuser) groups=1000(mockuser)",
            "uname -a": "Linux mockhost 5.4.0 #1 SMP PREEMPT x86_64 GNU/Linux",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nmockuser:x:1000:1000::/home/mockuser:/bin/bash",
            "ps aux": "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0.0 0.1 1234 567 ? Ss 00:00 0:01 /sbin/init",
            "netstat -tulpn": "Active Internet connections\nProto Local Address State PID/Program\ntcp 0.0.0.0:80 LISTEN 1234/apache2"
        }
        
        # Look for exact matches first
        if command in mock_responses:
            mock_output = mock_responses[command]
        # Check for partial matches
        elif any(cmd in command for cmd in mock_responses.keys()):
            matching_cmd = next(cmd for cmd in mock_responses.keys() if cmd in command)
            mock_output = mock_responses[matching_cmd]
        # Generic response for unknown commands
        else:
            mock_output = f"MOCK: Command '{command}' executed successfully\nMOCK OUTPUT: [simulated response]"
        
        output = f"Command: {command}\n"
        output += f"Return code: 0\n"
        output += f"Output: {mock_output}\n"
        
        return {
            "content": [{"type": "text", "text": output}],
            "isError": False
        }

    async def tool_query_database(self, arguments):
        """VULNERABLE: SQL Injection"""
        query = arguments.get("query", "")
        user_id = arguments.get("user_id", "")
        
        if not self.vulnerable:
            return {
                "content": [{"type": "text", "text": "Database queries disabled in safe mode"}],
                "isError": False
            }
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # INTENTIONALLY VULNERABLE: SQL Injection
            if user_id:
                full_query = f"SELECT * FROM users WHERE id = {user_id} AND ({query})"
            else:
                full_query = query
            
            logger.warning(f"Executing potentially dangerous SQL: {full_query}")
            cursor.execute(full_query)
            results = cursor.fetchall()
            
            # Get column names
            columns = [description[0] for description in cursor.description]
            
            # Format results
            output = f"Query: {full_query}\n"
            output += f"Results ({len(results)} rows):\n"
            
            for row in results:
                row_dict = dict(zip(columns, row))
                output += f"  {row_dict}\n"
            
            conn.close()
            
            return {
                "content": [{"type": "text", "text": output}],
                "isError": False
            }
            
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Database error: {str(e)}"}],
                "isError": True
            }

    async def tool_read_file(self, arguments):
        """MOCK: Simulated file reading (SAFE - NO ACTUAL FILE ACCESS)"""
        file_path = arguments.get("file_path", "")
        
        if not self.vulnerable:
            return {
                "content": [{"type": "text", "text": "File reading disabled in safe mode"}],
                "isError": False
            }
        
        # MOCK RESPONSES - NO ACTUAL FILE READING FOR SAFETY
        logger.info(f"MOCK: Simulating file read for: {file_path}")
        
        # Generate mock file contents based on common paths
        mock_files = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nmockuser:x:1000:1000::/home/mockuser:/bin/bash",
            "/etc/shadow": "root:$6$mockhashedpassword:18500:0:99999:7:::\nmockuser:$6$anothermockhash:18500:0:99999:7:::",
            "/etc/hosts": "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback",
            "/proc/version": "Linux version 5.4.0-74-generic (buildd@mockhost) (gcc version 9.4.0)",
            "config.json": '{\n  "database": {\n    "host": "localhost",\n    "password": "secret123"\n  }\n}',
            "secrets.txt": "API_KEY=sk-1234567890abcdef\nDATABASE_PASSWORD=supersecret\nADMIN_TOKEN=admin_token_here",
            ".env": "DB_PASSWORD=secret123\nAPI_KEY=sk-abcdef\nSECRET_KEY=topsecret"
        }
        
        # Check for exact matches
        if file_path in mock_files:
            mock_content = mock_files[file_path]
        # Check for partial matches (e.g., any config.json, .env files)
        elif any(pattern in file_path.lower() for pattern in ["config", "secret", ".env", "passwd", "shadow"]):
            if "config" in file_path.lower():
                mock_content = mock_files["config.json"]
            elif "secret" in file_path.lower():
                mock_content = mock_files["secrets.txt"]
            elif ".env" in file_path.lower():
                mock_content = mock_files[".env"]
            elif "passwd" in file_path.lower():
                mock_content = mock_files["/etc/passwd"]
            elif "shadow" in file_path.lower():
                mock_content = mock_files["/etc/shadow"]
            else:
                mock_content = "MOCK: File content simulation\nThis is mock file content for testing purposes."
        # Generic response for unknown files
        else:
            mock_content = f"MOCK: Contents of {file_path}\nLine 1: Mock file content\nLine 2: This is simulated data\nLine 3: Not real file contents"
        
        output = f"File: {file_path}\n"
        output += f"Content ({len(mock_content)} chars):\n"
        output += mock_content[:1000]  # Limit output
        if len(mock_content) > 1000:
            output += "\n... (truncated)"
        
        return {
            "content": [{"type": "text", "text": output}],
            "isError": False
        }

    async def tool_generate_report(self, arguments):
        """VULNERABLE: XSS in HTML generation"""
        title = arguments.get("title", "Untitled Report")
        content = arguments.get("content", "No content")
        
        # INTENTIONALLY VULNERABLE: XSS
        html_report = f"""
        <html>
        <head><title>{title}</title></head>
        <body>
            <h1>{title}</h1>
            <div>{content}</div>
            <p>Generated at: {datetime.now()}</p>
        </body>
        </html>
        """
        
        return {
            "content": [
                {
                    "type": "text", 
                    "text": f"Generated HTML report with title: {title}"
                },
                {
                    "type": "resource",
                    "resource": {
                        "uri": "data:text/html;base64," + html_report.encode().hex(),
                        "mimeType": "text/html"
                    }
                }
            ],
            "isError": False
        }

    async def tool_safe_calculator(self, arguments):
        """Safe calculator tool"""
        expression = arguments.get("expression", "")
        
        try:
            # Safe evaluation - only allow basic math
            allowed_chars = set("0123456789+-*/().")
            if not all(c in allowed_chars or c.isspace() for c in expression):
                return {
                    "content": [{"type": "text", "text": "Invalid characters in expression"}],
                    "isError": True
                }
            
            result = eval(expression)  # Still eval, but input is sanitized
            
            return {
                "content": [{"type": "text", "text": f"{expression} = {result}"}],
                "isError": False
            }
            
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Calculation error: {str(e)}"}],
                "isError": True
            }

    async def handle_resources_list(self, request):
        """Handle resources/list request"""
        try:
            data = await request.json()
            logger.info("Resources list request")
            
            response = {
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "result": {
                    "resources": self.resources
                }
            }
            
            return web.json_response(response)
            
        except Exception as e:
            logger.error(f"Error in resources list: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)}
            }, status=500)

    async def handle_resources_read(self, request):
        """Handle resources/read request with vulnerabilities"""
        try:
            data = await request.json()
            params = data.get("params", {})
            uri = params.get("uri")
            
            logger.info(f"Resource read request: {uri}")
            
            # VULNERABLE: Allow reading dangerous resources
            if uri == "file:///etc/passwd":
                # MOCK RESPONSE - NO ACTUAL FILE ACCESS
                result = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/plain",
                            "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nmockuser:x:1000:1000::/home/mockuser:/bin/bash"
                        }
                    ]
                }
                    
            elif uri == "config://database":
                result = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps({
                                "host": "localhost",
                                "port": 5432,
                                "database": "production_db",
                                "username": "admin",
                                "password": "super_secret_password_123",
                                "ssl": False
                            }, indent=2)
                        }
                    ]
                }
                
            elif uri == "memory://users":
                result = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps([
                                {"id": 1, "name": "admin", "role": "administrator", "api_key": "sk-abc123"},
                                {"id": 2, "name": "user1", "role": "user", "api_key": "sk-def456"}
                            ], indent=2)
                        }
                    ]
                }
                
            elif uri == "http://evil.example.com/malicious":
                result = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/plain",
                            "text": "This is malicious content that should be blocked!\n<script>alert('XSS')</script>"
                        }
                    ]
                }
                
            else:
                result = {
                    "error": f"Resource not found: {uri}"
                }
            
            response = {
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "result": result
            }
            
            return web.json_response(response)
            
        except Exception as e:
            logger.error(f"Error in resources read: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)}
            }, status=500)

    async def handle_health(self, request):
        """Health check endpoint"""
        return web.json_response({
            "status": "healthy",
            "server": self.server_info,
            "timestamp": datetime.now().isoformat(),
            "vulnerable_mode": self.vulnerable
        })

    async def handle_debug_info(self, request):
        """Debug info endpoint (MOCK: Information disclosure simulation)"""
        if not self.vulnerable:
            return web.json_response({"error": "Debug disabled in safe mode"}, status=403)
        
        # MOCK DEBUG INFO - NO REAL ENVIRONMENT OR SYSTEM DATA
        debug_info = {
            "server_info": self.server_info,
            "tools_count": len(self.tools),
            "resources_count": len(self.resources),
            "database_path": "/tmp/mock_mcp_test.db",
            "environment_vars": {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": "/home/mockuser",
                "USER": "mockuser",
                "SECRET_API_KEY": "sk-mock1234567890abcdef",
                "DATABASE_PASSWORD": "mocksecret123",
                "AWS_ACCESS_KEY_ID": "AKIAMOCKKEY123456789",
                "AWS_SECRET_ACCESS_KEY": "mockSecretKey123456789abcdefghijklmnop"
            },
            "current_directory": "/opt/mock-mcp-server",
            "process_id": 12345,
            "vulnerable_endpoints": [
                "/mcp/tools/call -> execute_command (RCE)",
                "/mcp/tools/call -> query_database (SQLi)",
                "/mcp/tools/call -> read_file (Path Traversal)",
                "/mcp/tools/call -> generate_report (XSS)",
                "/mcp/resources/read -> file:// (LFI)",
                "/debug/info (Information Disclosure)"
            ],
            "internal_config": {
                "admin_password": "admin123",
                "jwt_secret": "mock_jwt_secret_key_123",
                "encryption_key": "mock_encryption_key_456"
            }
        }
        
        return web.json_response(debug_info)

    async def handle_websocket(self, request):
        """WebSocket endpoint for MCP over WebSocket"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        logger.info("WebSocket connection established")
        
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    logger.info(f"WebSocket message: {data}")
                    
                    # Echo back for now - could implement full MCP over WS
                    response = {
                        "jsonrpc": "2.0",
                        "id": data.get("id"),
                        "result": {"echo": data, "timestamp": datetime.now().isoformat()}
                    }
                    
                    await ws.send_str(json.dumps(response))
                    
                except json.JSONDecodeError:
                    await ws.send_str(json.dumps({
                        "jsonrpc": "2.0",
                        "error": {"code": -32700, "message": "Parse error"}
                    }))
                    
            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error: {ws.exception()}")
                break
        
        logger.info("WebSocket connection closed")
        return ws

    async def start_server(self):
        """Start the mock MCP server"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        
        mode = "VULNERABLE" if self.vulnerable else "SAFE"
        logger.info(f"Mock MCP Server started in {mode} mode")
        logger.info(f"Server: http://{self.host}:{self.port}")
        logger.info(f"Health: http://{self.host}:{self.port}/health")
        if self.vulnerable:
            logger.info(f"Debug: http://{self.host}:{self.port}/debug/info")
        logger.info(f"WebSocket: ws://{self.host}:{self.port}/ws")
        
        return runner

async def main():
    parser = argparse.ArgumentParser(description="Mock MCP Server for Security Testing")
    parser.add_argument("--host", default="localhost", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--safe", action="store_true", help="Run in safe mode (no vulnerabilities)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    vulnerable = not args.safe
    server = MockMCPServer(args.host, args.port, vulnerable)
    
    try:
        runner = await server.start_server()
        
        print(f"\n🚀 Mock MCP Server running on http://{args.host}:{args.port}")
        print(f"Mode: {'MOCK VULNERABLE' if vulnerable else 'SAFE'}")
        print("\nEndpoints:")
        print(f"  POST /mcp/initialize")
        print(f"  POST /mcp/tools/list")
        print(f"  POST /mcp/tools/call")
        print(f"  POST /mcp/resources/list")
        print(f"  POST /mcp/resources/read")
        print(f"  GET  /health")
        if vulnerable:
            print(f"  GET  /debug/info (MOCK VULNERABLE)")
        print(f"  WS   /ws")
        
        print(f"\nTesting:")
        print(f"  curl http://{args.host}:{args.port}/health")
        print(f"  ./mcpscan scan-remote http://{args.host}:{args.port} critical-security")
        
        if vulnerable:
            print(f"\n✅ SAFE: Server simulates vulnerabilities with mock responses only!")
            print(f"   No real commands are executed or files accessed.")
            print(f"   Safe for testing and development environments.")
        
        print(f"\nPress Ctrl+C to stop")
        
        # Keep running until interrupted
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
