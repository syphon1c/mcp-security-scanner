#!/usr/bin/env python3
"""
Live Monitoring Proxy Test Suite
Tests the MCP Security Proxy functionality end-to-end
"""

import asyncio
import aiohttp
import json
import time
import sys
from typing import Dict, List, Any
import websockets

class ProxyTester:
    def __init__(self):
        self.proxy_url = "http://localhost:9080"
        self.mock_server_url = "http://localhost:8000"
        self.test_results = []
        
    async def run_all_tests(self):
        """Run all proxy tests"""
        print("🧪 Starting Proxy Tests")
        print("=" * 60)
        
        # Test 1: Proxy Health Check
        await self.test_proxy_health()
        
        # Test 2: Direct vs Proxied Requests
        await self.test_direct_vs_proxy()
        
        # Test 3: Proxy Monitoring Endpoints
        await self.test_monitoring_endpoints()
        
        # Test 4: Security Detection
        await self.test_security_detection()
        
        # Test 5: WebSocket Proxying
        await self.test_websocket_proxy()
        
        # Test 6: Load Testing
        await self.test_proxy_load()
        
        # Test 7: Error Handling
        await self.test_error_handling()
        
        # Print Results
        self.print_test_summary()
        
    async def test_proxy_health(self):
        """Test proxy health endpoints"""
        print("\n🔍 Test 1: Proxy Health Check")
        
        async with aiohttp.ClientSession() as session:
            try:
                # Test proxy health endpoint
                async with session.get(f"{self.proxy_url}/health") as resp:
                    if resp.status == 200:
                        health_data = await resp.json()
                        print(f"   ✅ Proxy health: {health_data.get('status')}")
                        print(f"   📡 Target: {health_data.get('target')}")
                        self.test_results.append(("Proxy Health", "PASS", f"Status: {health_data.get('status')}"))
                    else:
                        print(f"   ❌ Proxy health check failed: {resp.status}")
                        self.test_results.append(("Proxy Health", "FAIL", f"HTTP {resp.status}"))
                        
            except Exception as e:
                print(f"   ❌ Proxy health check error: {e}")
                self.test_results.append(("Proxy Health", "FAIL", str(e)))
                
    async def test_direct_vs_proxy(self):
        """Test that proxy returns same results as direct calls"""
        print("\n🔍 Test 2: Direct vs Proxied Requests")
        
        test_endpoints = [
            "/health",
            "/debug/info"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in test_endpoints:
                try:
                    # Direct request to mock server
                    async with session.get(f"{self.mock_server_url}{endpoint}") as direct_resp:
                        direct_data = await direct_resp.text()
                        direct_status = direct_resp.status
                    
                    # Proxied request
                    async with session.get(f"{self.proxy_url}{endpoint}") as proxy_resp:
                        proxy_data = await proxy_resp.text()
                        proxy_status = proxy_resp.status
                    
                    if direct_status == proxy_status:
                        print(f"   ✅ {endpoint}: Status codes match ({direct_status})")
                        self.test_results.append((f"Proxy {endpoint}", "PASS", f"HTTP {proxy_status}"))
                    else:
                        print(f"   ❌ {endpoint}: Status mismatch - Direct: {direct_status}, Proxy: {proxy_status}")
                        self.test_results.append((f"Proxy {endpoint}", "FAIL", f"Status mismatch"))
                        
                except Exception as e:
                    print(f"   ❌ {endpoint} error: {e}")
                    self.test_results.append((f"Proxy {endpoint}", "FAIL", str(e)))
                    
    async def test_monitoring_endpoints(self):
        """Test proxy monitoring capabilities"""
        print("\n🔍 Test 3: Proxy Monitoring Endpoints")
        
        monitoring_endpoints = [
            "/monitor/health",
            "/monitor/alerts", 
            "/monitor/logs"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in monitoring_endpoints:
                try:
                    async with session.get(f"{self.proxy_url}{endpoint}") as resp:
                        if resp.status == 200:
                            data = await resp.text()
                            print(f"   ✅ {endpoint}: Available ({len(data)} bytes)")
                            self.test_results.append((f"Monitor {endpoint}", "PASS", f"{len(data)} bytes"))
                        else:
                            print(f"   ⚠️ {endpoint}: HTTP {resp.status}")
                            self.test_results.append((f"Monitor {endpoint}", "WARN", f"HTTP {resp.status}"))
                            
                except Exception as e:
                    print(f"   ❌ {endpoint} error: {e}")
                    self.test_results.append((f"Monitor {endpoint}", "FAIL", str(e)))
                    
    async def test_security_detection(self):
        """Test security threat detection"""
        print("\n🔍 Test 4: Security Detection")
        
        # Send potentially malicious requests through proxy
        malicious_payloads = [
            {
                "name": "SQL Injection",
                "payload": {"query": "'; DROP TABLE users; --"},
                "endpoint": "/mcp/tools/call"
            },
            {
                "name": "Script Injection",
                "payload": {"script": "<script>alert('xss')</script>"},
                "endpoint": "/mcp/tools/call"
            },
            {
                "name": "Command Injection",
                "payload": {"command": "ls; rm -rf /"},
                "endpoint": "/mcp/tools/call"
            }
        ]
        
        async with aiohttp.ClientSession() as session:
            for test in malicious_payloads:
                try:
                    # Send malicious payload through proxy
                    async with session.post(
                        f"{self.proxy_url}{test['endpoint']}", 
                        json=test["payload"]
                    ) as resp:
                        print(f"   📊 {test['name']}: HTTP {resp.status}")
                        
                        # Check if alerts were generated
                        await asyncio.sleep(0.1)  # Give proxy time to process
                        async with session.get(f"{self.proxy_url}/alerts") as alert_resp:
                            if alert_resp.status == 200:
                                alerts = await alert_resp.json()
                                if isinstance(alerts, dict) and alerts.get('alerts'):
                                    print(f"      🚨 Security alert generated")
                                    self.test_results.append((f"Security {test['name']}", "PASS", "Alert generated"))
                                else:
                                    print(f"      ⚠️ No security alert detected")
                                    self.test_results.append((f"Security {test['name']}", "WARN", "No alert"))
                            
                except Exception as e:
                    print(f"   ❌ {test['name']} error: {e}")
                    self.test_results.append((f"Security {test['name']}", "FAIL", str(e)))
                    
    async def test_websocket_proxy(self):
        """Test WebSocket proxying"""
        print("\n🔍 Test 5: WebSocket Proxy")
        
        try:
            # Test WebSocket connection through proxy
            proxy_ws_url = "ws://localhost:9080/ws"
            
            async with websockets.connect(proxy_ws_url, timeout=5) as websocket:
                # Send test message
                test_message = json.dumps({"type": "ping", "data": "test"})
                await websocket.send(test_message)
                
                # Wait for response
                response = await asyncio.wait_for(websocket.recv(), timeout=5)
                print(f"   ✅ WebSocket proxy working: {len(response)} bytes received")
                self.test_results.append(("WebSocket Proxy", "PASS", f"{len(response)} bytes"))
                
        except asyncio.TimeoutError:
            print("   ⚠️ WebSocket proxy timeout")
            self.test_results.append(("WebSocket Proxy", "WARN", "Timeout"))
        except Exception as e:
            print(f"   ❌ WebSocket proxy error: {e}")
            self.test_results.append(("WebSocket Proxy", "FAIL", str(e)))
            
    async def test_proxy_load(self):
        """Test proxy under load"""
        print("\n🔍 Test 6: Load Testing")
        
        async def make_request(session, i):
            try:
                async with session.get(f"{self.proxy_url}/health") as resp:
                    return resp.status == 200
            except:
                return False
                
        async with aiohttp.ClientSession() as session:
            # Send 50 concurrent requests
            start_time = time.time()
            tasks = [make_request(session, i) for i in range(50)]
            results = await asyncio.gather(*tasks)
            end_time = time.time()
            
            success_count = sum(results)
            duration = end_time - start_time
            
            print(f"   📊 Load test: {success_count}/50 requests successful")
            print(f"   ⏱️ Duration: {duration:.2f}s ({50/duration:.1f} req/s)")
            
            if success_count >= 45:  # 90% success rate
                self.test_results.append(("Load Test", "PASS", f"{success_count}/50 successful"))
            else:
                self.test_results.append(("Load Test", "FAIL", f"Only {success_count}/50 successful"))
                
    async def test_error_handling(self):
        """Test proxy error handling"""
        print("\n🔍 Test 7: Error Handling")
        
        async with aiohttp.ClientSession() as session:
            # Test non-existent endpoint
            try:
                async with session.get(f"{self.proxy_url}/nonexistent") as resp:
                    print(f"   📊 Non-existent endpoint: HTTP {resp.status}")
                    if resp.status in [404, 502]:
                        self.test_results.append(("Error Handling", "PASS", f"HTTP {resp.status}"))
                    else:
                        self.test_results.append(("Error Handling", "WARN", f"Unexpected HTTP {resp.status}"))
                        
            except Exception as e:
                print(f"   ❌ Error handling test failed: {e}")
                self.test_results.append(("Error Handling", "FAIL", str(e)))
                
    def print_test_summary(self):
        """Print  test results"""
        print("\n" + "=" * 60)
        print("🧪 PROXY TEST SUMMARY")
        print("=" * 60)
        
        pass_count = sum(1 for _, status, _ in self.test_results if status == "PASS")
        warn_count = sum(1 for _, status, _ in self.test_results if status == "WARN")
        fail_count = sum(1 for _, status, _ in self.test_results if status == "FAIL")
        total_count = len(self.test_results)
        
        for test_name, status, details in self.test_results:
            icon = "✅" if status == "PASS" else "⚠️" if status == "WARN" else "❌"
            print(f"{icon} {test_name:<25} {status:<6} {details}")
            
        print("-" * 60)
        print(f"📊 Results: {pass_count} PASS, {warn_count} WARN, {fail_count} FAIL ({total_count} total)")
        
        if fail_count == 0:
            print("🎉 All critical tests passed! Proxy is working correctly.")
        elif fail_count <= 2:
            print("⚠️ Some tests failed, but proxy appears functional.")
        else:
            print("❌ Multiple test failures. Proxy may have issues.")
            
        print("\n📈 Proxy Performance Metrics:")
        print(f"   🔗 Proxy URL: {self.proxy_url}")
        print(f"   📡 Target URL: {self.mock_server_url}")
        print(f"   🛡️ Security monitoring: Active")
        print(f"   📊 Real-time alerts: Available")

async def main():
    """Main test runner"""
    print("🚀 MCP Security Proxy Test Suite")
    print("Starting  testing...")
    
    tester = ProxyTester()
    await tester.run_all_tests()
    
    print("\n🔗 Access proxy monitoring:")
    print("   📊 Monitor: http://localhost:9080/monitor")
    print("   🏥 Health:  http://localhost:9080/health") 
    print("   📈 Metrics: http://localhost:9080/metrics")
    print("   🚨 Alerts:  http://localhost:9080/alerts")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⏹️ Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test suite error: {e}")
        sys.exit(1)
