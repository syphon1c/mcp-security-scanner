#!/usr/bin/env python3
"""
Test script for the Mock MCP Server

This script tests the basic functionality of the mock MCP server
to ensure it responds correctly to MCP protocol messages.
"""

import json
import requests
import sys

def test_mcp_server(base_url="http://localhost:8000"):
    """Test the mock MCP server endpoints"""
    
    print(f"🧪 Testing Mock MCP Server at {base_url}")
    
    # Test 1: Health check
    print("\n1. Testing health endpoint...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print(f"   ✅ Health check passed: {health_data['status']}")
            print(f"   Server: {health_data['server']['name']} v{health_data['server']['version']}")
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Health check error: {e}")
        return False
    
    # Test 2: MCP Initialize
    print("\n2. Testing MCP initialize...")
    try:
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "clientInfo": {
                    "name": "MCP Security Scanner Test",
                    "version": "1.0.0"
                }
            }
        }
        
        response = requests.post(
            f"{base_url}/mcp/initialize",
            json=init_request,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            init_data = response.json()
            if "result" in init_data:
                print(f"   ✅ Initialize successful")
                print(f"   Protocol: {init_data['result']['protocolVersion']}")
                print(f"   Capabilities: {list(init_data['result']['capabilities'].keys())}")
            else:
                print(f"   ❌ Initialize failed: {init_data}")
                return False
        else:
            print(f"   ❌ Initialize failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Initialize error: {e}")
        return False
    
    # Test 3: Tools List
    print("\n3. Testing tools list...")
    try:
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        
        response = requests.post(
            f"{base_url}/mcp/tools/list",
            json=tools_request,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            tools_data = response.json()
            if "result" in tools_data:
                tools = tools_data["result"]["tools"]
                print(f"   ✅ Tools list successful: {len(tools)} tools")
                for tool in tools[:3]:  # Show first 3 tools
                    print(f"      - {tool['name']}: {tool['description']}")
                if len(tools) > 3:
                    print(f"      ... and {len(tools) - 3} more")
            else:
                print(f"   ❌ Tools list failed: {tools_data}")
                return False
        else:
            print(f"   ❌ Tools list failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Tools list error: {e}")
        return False
    
    # Test 4: Resources List
    print("\n4. Testing resources list...")
    try:
        resources_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/list",
            "params": {}
        }
        
        response = requests.post(
            f"{base_url}/mcp/resources/list",
            json=resources_request,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            resources_data = response.json()
            if "result" in resources_data:
                resources = resources_data["result"]["resources"]
                print(f"   ✅ Resources list successful: {len(resources)} resources")
                for resource in resources[:3]:  # Show first 3 resources
                    print(f"      - {resource['uri']}: {resource['name']}")
                if len(resources) > 3:
                    print(f"      ... and {len(resources) - 3} more")
            else:
                print(f"   ❌ Resources list failed: {resources_data}")
                return False
        else:
            print(f"   ❌ Resources list failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Resources list error: {e}")
        return False
    
    # Test 5: Safe Tool Call
    print("\n5. Testing safe tool call...")
    try:
        safe_call_request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "safe_calculator",
                "arguments": {
                    "expression": "2 + 2"
                }
            }
        }
        
        response = requests.post(
            f"{base_url}/mcp/tools/call",
            json=safe_call_request,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            call_data = response.json()
            if "result" in call_data:
                result = call_data["result"]
                if "content" in result:
                    content = result["content"][0]["text"]
                    print(f"   ✅ Safe tool call successful: {content}")
                else:
                    print(f"   ❌ Safe tool call unexpected result: {result}")
            else:
                print(f"   ❌ Safe tool call failed: {call_data}")
                return False
        else:
            print(f"   ❌ Safe tool call failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Safe tool call error: {e}")
        return False
    
    # Test 6: Debug Info (Vulnerable endpoint)
    print("\n6. Testing debug info (vulnerable endpoint)...")
    try:
        response = requests.get(f"{base_url}/debug/info", timeout=5)
        if response.status_code == 200:
            debug_data = response.json()
            if "vulnerable_endpoints" in debug_data:
                print(f"   ⚠️  Debug info accessible (VULNERABLE)")
                print(f"   Found {len(debug_data['vulnerable_endpoints'])} vulnerable endpoints")
            else:
                print(f"   ❓ Debug info accessible but unexpected format")
        elif response.status_code == 403:
            print(f"   ✅ Debug info blocked (SAFE MODE)")
        else:
            print(f"   ❓ Debug info unexpected status: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Debug info error: {e}")
    
    print(f"\n🎉 Mock MCP Server test completed successfully!")
    print(f"🎯 Server is ready for security scanning with:")
    print(f"   ./mcpscan scan-remote {base_url} critical-security")
    print(f"   ./mcpscan scan-remote {base_url} advanced-polymorphic-security")
    
    return True

if __name__ == "__main__":
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:8000"
    
    success = test_mcp_server(base_url)
    sys.exit(0 if success else 1)
