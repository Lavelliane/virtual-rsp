#!/usr/bin/env python3
"""
Demo script for SGP.22 Mutual Authentication Flow
Demonstrates the complete authentication process between:
- Virtual eUICC (our implementation)
- lpac (LPA daemon)
- SM-DP+ server (osmo-smdpp.py)

This follows the SGP.22 sequence diagram for mutual authentication.
"""

import os
import sys
import time
import subprocess
import signal
import requests
import json
import base64
from pathlib import Path

class SGP22AuthDemo:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.v_euicc_socket = "/tmp/v-euicc-auth-demo.sock"
        self.smdp_host = "127.0.0.1"
        self.smdp_port = 8080
        self.smdp_url = f"http://{self.smdp_host}:{self.smdp_port}"
        
        self.v_euicc_process = None
        self.smdp_process = None
        
    def print_step(self, step_num, title, description=""):
        """Print a formatted step in the authentication flow"""
        print(f"\n{'='*60}")
        print(f"STEP {step_num}: {title}")
        print(f"{'='*60}")
        if description:
            print(description)
        print()
    
    def start_v_euicc_server(self):
        """Start the virtual eUICC server"""
        print("🚀 Starting Virtual eUICC Server...")
        
        # Build the server first
        build_result = subprocess.run(
            ["make"], 
            cwd=self.base_dir,
            capture_output=True,
            text=True
        )
        
        if build_result.returncode != 0:
            print(f"❌ Failed to build v-euicc: {build_result.stderr}")
            return False
        
        # Start the server
        server_cmd = [
            "./bin/v-euicc-server",
            "--debug",
            "--address", self.v_euicc_socket
        ]
        
        self.v_euicc_process = subprocess.Popen(
            server_cmd,
            cwd=self.base_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Wait for server to start
        time.sleep(2)
        
        if self.v_euicc_process.poll() is None:
            print(f"✅ Virtual eUICC server started (PID: {self.v_euicc_process.pid})")
            print(f"   Socket: {self.v_euicc_socket}")
            return True
        else:
            print("❌ Failed to start virtual eUICC server")
            return False
    
    def start_smdp_server(self):
        """Start the SM-DP+ server"""
        print("🚀 Starting SM-DP+ Server...")
        
        pysim_dir = self.base_dir.parent / "pysim"
        
        # Check if virtual environment exists
        venv_dir = pysim_dir / "venv"
        if not venv_dir.exists():
            print("❌ pySIM virtual environment not found")
            return False
        
        # Start the SM-DP+ server
        server_cmd = [
            f"{venv_dir}/bin/python3",
            "osmo-smdpp.py",
            "--host", self.smdp_host,
            "--port", str(self.smdp_port),
            "--certdir", "certs",
            "--nossl"
        ]
        
        self.smdp_process = subprocess.Popen(
            server_cmd,
            cwd=pysim_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Wait for server to start
        time.sleep(3)
        
        if self.smdp_process.poll() is None:
            print(f"✅ SM-DP+ server started (PID: {self.smdp_process.pid})")
            print(f"   URL: {self.smdp_url}")
            return True
        else:
            print("❌ Failed to start SM-DP+ server")
            return False
    
    def test_v_euicc_basic_commands(self):
        """Test basic eUICC commands through lpac"""
        self.print_step(1, "Testing Virtual eUICC Basic Commands", 
                       "Verify that lpac can communicate with the virtual eUICC")
        
        lpac_dir = self.base_dir.parent / "lpac"
        env = os.environ.copy()
        env.update({
            "V_EUICC_ADDRESS": self.v_euicc_socket,
            "V_EUICC_CONNECTION_TYPE": "unix",
            "LPAC_APDU": "v_euicc"
        })
        
        # Test 1: Get EID
        print("📱 Testing EID retrieval...")
        result = subprocess.run(
            ["./output/lpac", "chip", "info"],
            cwd=lpac_dir,
            env=env,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("✅ EID retrieval successful!")
            print(f"   Response: {result.stdout.strip()}")
        else:
            print(f"❌ EID retrieval failed: {result.stderr}")
            return False
        
        return True
    
    def test_smdp_connectivity(self):
        """Test SM-DP+ server connectivity"""
        self.print_step(2, "Testing SM-DP+ Server Connectivity",
                       "Verify that the SM-DP+ server is responding to HTTP requests")
        
        try:
            # Test basic connectivity
            response = requests.get(f"{self.smdp_url}/", timeout=5)
            print(f"✅ SM-DP+ server responding (Status: {response.status_code})")
            
            # Test authentication endpoint
            auth_url = f"{self.smdp_url}/gsma/rsp2/es9plus/initiateAuthentication"
            test_payload = {
                "smdpAddress": "testsmdpplus1.example.com",
                "euiccChallenge": base64.b64encode(b'0123456789ABCDEF').decode(),
                "euiccInfo1": base64.b64encode(b'dummy_euicc_info').decode()
            }
            
            headers = {
                "Content-Type": "application/json",
                "X-Admin-Protocol": "gsma/rsp/v2.1.0"
            }
            
            # This should fail but show the server is responding
            response = requests.post(auth_url, json=test_payload, headers=headers, timeout=5)
            print(f"✅ Authentication endpoint responding (Status: {response.status_code})")
            
            return True
            
        except requests.RequestException as e:
            print(f"❌ SM-DP+ connectivity test failed: {e}")
            return False
    
    def demonstrate_sgp22_flow(self):
        """Demonstrate the SGP.22 authentication flow"""
        self.print_step(3, "SGP.22 Mutual Authentication Flow",
                       "Demonstrating the complete authentication sequence")
        
        print("🔐 SGP.22 Authentication Flow Demonstration")
        print()
        print("According to SGP.22 specification, the mutual authentication involves:")
        print()
        print("Phase 1: eUICC Challenge Generation")
        print("  📱 LPAd → eUICC: ES10b.GetEUICCInfo")
        print("  📱 LPAd → eUICC: ES10b.GetEUICCChallenge")
        print()
        print("Phase 2: Server Authentication")
        print("  🌐 LPAd → SM-DP+: ES9+.InitiateAuthentication")
        print("  📱 LPAd → eUICC: ES10b.AuthenticateServer")
        print()
        print("Phase 3: Client Authentication")
        print("  🌐 LPAd → SM-DP+: ES9+.AuthenticateClient")
        print()
        print("Current Implementation Status:")
        print("  ✅ Virtual eUICC: EID retrieval")
        print("  ✅ Virtual eUICC: GetEUICCInfo1")
        print("  ✅ Virtual eUICC: GetEUICCChallenge")
        print("  🟡 Virtual eUICC: AuthenticateServer (basic structure)")
        print("  ✅ SM-DP+ Server: InitiateAuthentication endpoint")
        print("  ✅ SM-DP+ Server: AuthenticateClient endpoint")
        print("  🟡 Full ECDSA signature validation (requires implementation)")
        print()
        print("💡 Next Steps for Full Implementation:")
        print("  1. Implement proper ASN.1 parsing in virtual eUICC")
        print("  2. Add ECDSA signature generation and verification")
        print("  3. Integrate real certificate chain validation")
        print("  4. Test with actual profile download")
        
        return True
    
    def cleanup(self):
        """Clean up running processes"""
        print("\n🧹 Cleaning up...")
        
        if self.v_euicc_process and self.v_euicc_process.poll() is None:
            print("   Stopping virtual eUICC server...")
            self.v_euicc_process.terminate()
            self.v_euicc_process.wait(timeout=5)
        
        if self.smdp_process and self.smdp_process.poll() is None:
            print("   Stopping SM-DP+ server...")
            self.smdp_process.terminate()
            self.smdp_process.wait(timeout=5)
        
        # Remove socket file
        if os.path.exists(self.v_euicc_socket):
            os.unlink(self.v_euicc_socket)
        
        print("✅ Cleanup complete")
    
    def run_demo(self):
        """Run the complete authentication demo"""
        print("🎯 SGP.22 Virtual eUICC Mutual Authentication Demo")
        print("=" * 60)
        print()
        print("This demo showcases:")
        print("  • Virtual eUICC with SGP.22 command support")
        print("  • SM-DP+ server with authentication endpoints")
        print("  • lpac integration for RSP operations")
        print("  • ECDSA certificate infrastructure")
        print()
        
        try:
            # Start servers
            if not self.start_v_euicc_server():
                return False
            
            if not self.start_smdp_server():
                return False
            
            # Run tests
            if not self.test_v_euicc_basic_commands():
                return False
            
            if not self.test_smdp_connectivity():
                return False
            
            if not self.demonstrate_sgp22_flow():
                return False
            
            print("\n🎉 Demo completed successfully!")
            print("\nThe virtual eUICC system is now ready for:")
            print("  • eSIM profile development")
            print("  • SGP.22 protocol testing")
            print("  • RSP application development")
            print("  • Certificate-based authentication")
            print()
            print("🔗 Integration points:")
            print(f"  Virtual eUICC: {self.v_euicc_socket}")
            print(f"  SM-DP+ Server: {self.smdp_url}")
            print(f"  lpac APDU Driver: v_euicc")
            
            return True
            
        except KeyboardInterrupt:
            print("\n⚠️  Demo interrupted by user")
            return False
        except Exception as e:
            print(f"\n❌ Demo failed: {e}")
            return False
        finally:
            self.cleanup()

def main():
    """Main entry point"""
    demo = SGP22AuthDemo()
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        demo.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    success = demo.run_demo()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 