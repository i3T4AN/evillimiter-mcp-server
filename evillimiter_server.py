#!/usr/bin/env python3
"""
EvilLimiter MCP Server - Network bandwidth control and monitoring via EvilLimiter CLI wrapper
"""

import os
import sys
import logging
import json
import asyncio
import subprocess
import re
import shlex
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("evillimiter-server")

mcp = FastMCP("evillimiter")

INTERFACE = os.environ.get("EVILLIMITER_INTERFACE", "")
GATEWAY_IP = os.environ.get("EVILLIMITER_GATEWAY_IP", "")
GATEWAY_MAC = os.environ.get("EVILLIMITER_GATEWAY_MAC", "")
NETMASK = os.environ.get("EVILLIMITER_NETMASK", "")
SAFETY_MODE = os.environ.get("EVILLIMITER_SAFETY_MODE", "true").lower() == "true"
ALLOWED_RANGES = os.environ.get("EVILLIMITER_ALLOWED_RANGES", "").split(",")
API_TOKEN = os.environ.get("EVILLIMITER_API_TOKEN", "")

# === UTILITY FUNCTIONS ===

def sanitize_input(user_input: str) -> str:
    """Sanitize user input to prevent command injection."""
    dangerous_chars = [';', '&', '|', '$', '`', '\\', '"', "'", '\n', '\r', '<', '>', '(', ')', '{', '}', '[', ']']
    clean_input = user_input
    for char in dangerous_chars:
        clean_input = clean_input.replace(char, '')
    return clean_input.strip()

def validate_ip_range(ip_range: str) -> bool:
    """Validate IP range format."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(-(\d{1,3}\.){3}\d{1,3}|/\d{1,2})?$'
    return bool(re.match(ip_pattern, ip_range))

def check_safety_mode(target_ips: str) -> bool:
    """Check if operation is allowed based on safety mode."""
    if not SAFETY_MODE:
        return True
    if not ALLOWED_RANGES:
        return True
    return any(allowed in target_ips for allowed in ALLOWED_RANGES if allowed)

async def run_evillimiter_command(command: str) -> str:
    """Run an EvilLimiter command and return output."""
    try:
        base_cmd = ["evillimiter"]
        
        if INTERFACE:
            base_cmd.extend(["-i", INTERFACE])
        if GATEWAY_IP:
            base_cmd.extend(["-g", GATEWAY_IP])
        if GATEWAY_MAC:
            base_cmd.extend(["-m", GATEWAY_MAC])
        if NETMASK:
            base_cmd.extend(["-n", NETMASK])
        
        full_cmd = f"echo '{command}; quit' | {' '.join(base_cmd)}"
        
        logger.info(f"Executing command: {command}")
        
        process = await asyncio.create_subprocess_shell(
            full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return "Command timed out after 30 seconds"
        
        output = stdout.decode('utf-8', errors='ignore')
        error = stderr.decode('utf-8', errors='ignore')
        
        if process.returncode != 0 and error:
            logger.error(f"Command error: {error}")
            return f"Error: {error}"
        
        lines = output.split('\n')
        cleaned_lines = []
        skip_banner = True
        for line in lines:
            if skip_banner:
                if 'type help or ?' in line.lower():
                    skip_banner = False
                continue
            if '(Main) >>>' in line:
                continue
            if line.strip():
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines) if cleaned_lines else output
        
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return f"Error executing command: {str(e)}"

# === MCP TOOLS ===

@mcp.tool()
async def scan_network(ip_range: str = "") -> str:
    """Scan network for online hosts - optionally specify IP range like 192.168.1.1-192.168.1.50."""
    logger.info(f"Scanning network with range: {ip_range}")
    
    try:
        if ip_range.strip():
            ip_range = sanitize_input(ip_range)
            if not validate_ip_range(ip_range):
                return "Error: Invalid IP range format"
            
            if not check_safety_mode(ip_range):
                return f"Safety mode: Scanning {ip_range} not allowed. Configure EVILLIMITER_ALLOWED_RANGES."
            
            command = f"scan --range {ip_range}"
        else:
            command = "scan"
        
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Scan failed: {result}"
        
        return f"Network scan completed:\n{result}"
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return f"Error scanning network: {str(e)}"

@mcp.tool()
async def list_hosts(force_show: str = "false") -> str:
    """List all scanned hosts with IDs and information - set force_show=true for wide tables."""
    logger.info("Listing hosts")
    
    try:
        command = "hosts --force" if force_show.lower() == "true" else "hosts"
        result = await run_evillimiter_command(command)
        
        if "no hosts" in result.lower() or not result.strip():
            return "No hosts found. Run scan_network first."
        
        return f"Current hosts:\n{result}"
        
    except Exception as e:
        logger.error(f"List hosts error: {e}")
        return f"Error listing hosts: {str(e)}"

@mcp.tool()
async def limit_bandwidth(host_ids: str = "", rate: str = "", direction: str = "both") -> str:
    """Limit bandwidth for hosts - IDs comma-separated or 'all', rate like 100kbit/1mbit, direction: both/upload/download."""
    logger.info(f"Limiting bandwidth for {host_ids} to {rate} ({direction})")
    
    try:
        if not host_ids.strip() or not rate.strip():
            return "Error: Both host_ids and rate are required"
        
        host_ids = sanitize_input(host_ids)
        rate = sanitize_input(rate)
        
        if not re.match(r'^\d+[kmg]?bit$', rate.lower()):
            return "Error: Invalid rate format. Use: 100kbit, 1mbit, 1gbit"
        
        command = f"limit {host_ids} {rate}"
        if direction == "upload":
            command += " --upload"
        elif direction == "download":
            command += " --download"
        
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Limit failed: {result}"
        
        return f"Bandwidth limited successfully:\n{result}"
        
    except Exception as e:
        logger.error(f"Limit error: {e}")
        return f"Error limiting bandwidth: {str(e)}"

@mcp.tool()
async def block_host(host_ids: str = "", direction: str = "both") -> str:
    """Block internet access for hosts - IDs comma-separated, direction: both/upload/download."""
    logger.info(f"Blocking hosts: {host_ids} ({direction})")
    
    try:
        if not host_ids.strip():
            return "Error: host_ids required"
        
        host_ids = sanitize_input(host_ids)
        
        command = f"block {host_ids}"
        if direction == "upload":
            command += " --upload"
        elif direction == "download":
            command += " --download"
        
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Block failed: {result}"
        
        return f"Hosts blocked successfully:\n{result}"
        
    except Exception as e:
        logger.error(f"Block error: {e}")
        return f"Error blocking hosts: {str(e)}"

@mcp.tool()
async def free_host(host_ids: str = "") -> str:
    """Remove all bandwidth limits and blocks from hosts - IDs comma-separated."""
    logger.info(f"Freeing hosts: {host_ids}")
    
    try:
        if not host_ids.strip():
            return "Error: host_ids required"
        
        host_ids = sanitize_input(host_ids)
        command = f"free {host_ids}"
        
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Free failed: {result}"
        
        return f"Hosts freed successfully:\n{result}"
        
    except Exception as e:
        logger.error(f"Free error: {e}")
        return f"Error freeing hosts: {str(e)}"

@mcp.tool()
async def add_host(ip_address: str = "", mac_address: str = "") -> str:
    """Manually add a host to the list - provide IP and optionally MAC address."""
    logger.info(f"Adding host: {ip_address} (MAC: {mac_address})")
    
    try:
        if not ip_address.strip():
            return "Error: IP address required"
        
        ip_address = sanitize_input(ip_address)
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_address):
            return "Error: Invalid IP address format"
        
        if not check_safety_mode(ip_address):
            return f"Safety mode: Adding {ip_address} not allowed"
        
        command = f"add {ip_address}"
        if mac_address.strip():
            mac_address = sanitize_input(mac_address)
            if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac_address):
                return "Error: Invalid MAC address format"
            command += f" --mac {mac_address}"
        
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Add failed: {result}"
        
        return f"Host added successfully:\n{result}"
        
    except Exception as e:
        logger.error(f"Add host error: {e}")
        return f"Error adding host: {str(e)}"

@mcp.tool()
async def monitor_bandwidth(interval_ms: str = "500") -> str:
    """Monitor bandwidth usage of limited hosts - interval in milliseconds (runs for 10 seconds)."""
    logger.info(f"Monitoring bandwidth with interval: {interval_ms}ms")
    
    try:
        interval_ms = sanitize_input(interval_ms)
        if not interval_ms.isdigit():
            return "Error: Interval must be a number in milliseconds"
        
        command = f"monitor --interval {interval_ms}"
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Monitor failed: {result}"
        
        return f"Bandwidth monitor (10s snapshot):\n{result}"
        
    except Exception as e:
        logger.error(f"Monitor error: {e}")
        return f"Error monitoring bandwidth: {str(e)}"

@mcp.tool()
async def analyze_traffic(host_ids: str = "", duration_seconds: str = "30") -> str:
    """Analyze traffic for hosts without limiting - IDs comma-separated, duration in seconds."""
    logger.info(f"Analyzing traffic for {host_ids} for {duration_seconds}s")
    
    try:
        if not host_ids.strip():
            return "Error: host_ids required"
        
        host_ids = sanitize_input(host_ids)
        duration_seconds = sanitize_input(duration_seconds)
        
        if not duration_seconds.isdigit():
            return "Error: Duration must be a number in seconds"
        
        command = f"analyze {host_ids} --duration {duration_seconds}"
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Analysis failed: {result}"
        
        return f"Traffic analysis complete:\n{result}"
        
    except Exception as e:
        logger.error(f"Analyze error: {e}")
        return f"Error analyzing traffic: {str(e)}"

@mcp.tool()
async def watch_status() -> str:
    """Show current watch status and monitored hosts."""
    logger.info("Getting watch status")
    
    try:
        result = await run_evillimiter_command("watch")
        
        if not result.strip():
            return "Watch list is empty"
        
        return f"Watch status:\n{result}"
        
    except Exception as e:
        logger.error(f"Watch status error: {e}")
        return f"Error getting watch status: {str(e)}"

@mcp.tool()
async def watch_add(host_ids: str = "") -> str:
    """Add hosts to watchlist for reconnection detection - IDs comma-separated."""
    logger.info(f"Adding to watchlist: {host_ids}")
    
    try:
        if not host_ids.strip():
            return "Error: host_ids required"
        
        host_ids = sanitize_input(host_ids)
        command = f"watch add {host_ids}"
        
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Watch add failed: {result}"
        
        return f"Added to watchlist:\n{result}"
        
    except Exception as e:
        logger.error(f"Watch add error: {e}")
        return f"Error adding to watchlist: {str(e)}"

@mcp.tool()
async def watch_remove(host_ids: str = "") -> str:
    """Remove hosts from watchlist - IDs comma-separated or 'all'."""
    logger.info(f"Removing from watchlist: {host_ids}")
    
    try:
        if not host_ids.strip():
            return "Error: host_ids required"
        
        host_ids = sanitize_input(host_ids)
        command = f"watch remove {host_ids}"
        
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Watch remove failed: {result}"
        
        return f"Removed from watchlist:\n{result}"
        
    except Exception as e:
        logger.error(f"Watch remove error: {e}")
        return f"Error removing from watchlist: {str(e)}"

@mcp.tool()
async def watch_configure(attribute: str = "", value: str = "") -> str:
    """Configure watch settings - attributes: range (IP range) or interval (seconds)."""
    logger.info(f"Configuring watch: {attribute}={value}")
    
    try:
        if not attribute.strip() or not value.strip():
            return "Error: Both attribute and value required"
        
        attribute = sanitize_input(attribute)
        value = sanitize_input(value)
        
        if attribute not in ["range", "interval"]:
            return "Error: Attribute must be 'range' or 'interval'"
        
        if attribute == "range" and not validate_ip_range(value):
            return "Error: Invalid IP range format"
        
        if attribute == "interval" and not value.isdigit():
            return "Error: Interval must be a number in seconds"
        
        command = f"watch set {attribute} {value}"
        result = await run_evillimiter_command(command)
        
        if "error" in result.lower():
            return f"Watch configure failed: {result}"
        
        return f"Watch configured:\n{result}"
        
    except Exception as e:
        logger.error(f"Watch configure error: {e}")
        return f"Error configuring watch: {str(e)}"

@mcp.tool()
async def flush_configuration() -> str:
    """Flush all iptables and tc configurations to reset network state."""
    logger.info("Flushing configuration")
    
    try:
        cmd = ["evillimiter", "-f"]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            return f"Flush failed: {stderr.decode('utf-8', errors='ignore')}"
        
        return "Network configuration flushed successfully"
        
    except Exception as e:
        logger.error(f"Flush error: {e}")
        return f"Error flushing configuration: {str(e)}"

# === SERVER STARTUP ===

if __name__ == "__main__":
    logger.info("Starting EvilLimiter MCP server...")
    logger.info(f"Safety mode: {SAFETY_MODE}")
    logger.info(f"Allowed ranges: {ALLOWED_RANGES if ALLOWED_RANGES else 'All (not restricted)'}")
    
    if not API_TOKEN:
        logger.warning("EVILLIMITER_API_TOKEN not set - authentication disabled")
    
    logger.warning("LEGAL NOTICE: This tool performs ARP spoofing and traffic manipulation.")
    logger.warning("Only use on networks you own or have explicit permission to test.")
    logger.warning("Unauthorized use may violate laws and regulations.")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
