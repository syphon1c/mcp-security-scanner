#!/usr/bin/env python3
"""
Mock LLM Server for testing MCP Security Scanner LLM Proxy
Simulates OpenAI-compatible API endpoints
"""

import json
import time
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class MockLLMHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/v1/models':
            self.send_models_response()
        elif self.path == '/health':
            self.send_health_response()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == '/v1/chat/completions':
            self.handle_chat_completion()
        elif self.path == '/v1/completions':
            self.handle_completion()
        else:
            self.send_error(404, "Not Found")

    def send_models_response(self):
        """Send mock models list"""
        response = {
            "object": "list",
            "data": [
                {
                    "id": "gpt-4",
                    "object": "model",
                    "created": 1677610602,
                    "owned_by": "openai"
                },
                {
                    "id": "gpt-3.5-turbo",
                    "object": "model", 
                    "created": 1677610602,
                    "owned_by": "openai"
                }
            ]
        }
        self.send_json_response(response)

    def send_health_response(self):
        """Send health check response"""
        response = {"status": "healthy", "timestamp": time.time()}
        self.send_json_response(response)

    def handle_chat_completion(self):
        """Handle chat completion requests"""
        try:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            request_data = json.loads(body.decode('utf-8'))
            
            # Extract prompt for logging
            messages = request_data.get('messages', [])
            last_message = messages[-1] if messages else {}
            prompt = last_message.get('content', 'No content')
            
            # Simulate security triggers for testing
            security_triggers = [
                "hack", "exploit", "bypass", "jailbreak", "ignore instructions",
                "credit card", "social security", "password", "api key"
            ]
            
            contains_trigger = any(trigger in prompt.lower() for trigger in security_triggers)
            
            if contains_trigger:
                # Simulate blocked request
                self.send_error(403, "Content policy violation detected")
                return
            
            # Generate mock response
            response = {
                "id": f"chatcmpl-{int(time.time())}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": request_data.get('model', 'gpt-3.5-turbo'),
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"This is a mock response to: {prompt[:50]}..."
                        },
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": len(prompt.split()),
                    "completion_tokens": random.randint(10, 100),
                    "total_tokens": len(prompt.split()) + random.randint(10, 100)
                }
            }
            
            # Add delay to simulate real API
            time.sleep(random.uniform(0.1, 0.5))
            
            self.send_json_response(response)
            
        except Exception as e:
            print(f"Error handling chat completion: {e}")
            self.send_error(500, str(e))

    def handle_completion(self):
        """Handle legacy completion requests"""
        try:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            request_data = json.loads(body.decode('utf-8'))
            
            prompt = request_data.get('prompt', '')
            
            # Generate mock response
            response = {
                "id": f"cmpl-{int(time.time())}",
                "object": "text_completion",
                "created": int(time.time()),
                "model": request_data.get('model', 'text-davinci-003'),
                "choices": [
                    {
                        "text": f" This is a mock completion for: {prompt[:30]}...",
                        "index": 0,
                        "logprobs": None,
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": len(prompt.split()),
                    "completion_tokens": random.randint(10, 50),
                    "total_tokens": len(prompt.split()) + random.randint(10, 50)
                }
            }
            
            self.send_json_response(response)
            
        except Exception as e:
            print(f"Error handling completion: {e}")
            self.send_error(500, str(e))

    def send_json_response(self, data, status=200):
        """Send JSON response"""
        response_json = json.dumps(data, indent=2)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_json)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response_json.encode('utf-8'))

    def log_message(self, format, *args):
        """Override to provide better logging"""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")

def main():
    port = 3030
    server_address = ('', port)
    
    print(f"🤖 Mock LLM Server starting on port {port}")
    print(f"   Chat Completions: http://localhost:{port}/v1/chat/completions")
    print(f"   Models:          http://localhost:{port}/v1/models")
    print(f"   Health:          http://localhost:{port}/health")
    print("   Simulates OpenAI-compatible API for testing")
    print()
    
    try:
        httpd = HTTPServer(server_address, MockLLMHandler)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Mock LLM Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == '__main__':
    main()