#!/usr/bin/env python3
import argparse
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify, abort
import logging
import threading
import time
import signal

# ASCII Art Banner
BANNER = """
=================================

 _____ _     _           _ 
|     |_|___| |_ ___ ___| |
| | | | |  _|   | .'| -_| |
|_|_|_|_|___|_|_|__,|___|_|
                                                                                                                                           

Node Agent - Upgraded Version 2.0-PRO
=================================
Managing LXC Containers with Ease
"""

# Print banner on startup
print(BANNER)

# Manual .env loader (no external deps)
def load_env(file_path='.env') -> Dict[str, str]:
    config = {}
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        match = re.match(r'^([^=]+)=(.*)$', line)
                        if match:
                            key, value = match.groups()
                            # Strip quotes if present
                            value = value.strip().strip('"\'')
                            config[key.strip()] = value
                        else:
                            logging.warning(f"Invalid .env line {line_num}: {line}")
        except Exception as e:
            logging.error(f"Failed to load .env: {e}")
    return config

# Configure logging (level from .env or default)
def setup_logging(log_level: str = 'INFO', log_file: str = 'node-agent.log'):
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

logger = logging.getLogger('node-agent')

app = Flask(__name__)

# Global config
API_KEY: Optional[str] = None
HOST: str = '0.0.0.0'
PORT: int = 5000
DEFAULT_TEMPLATE: str = '-t download -- -d ubuntu -r noble -a amd64'
HEALTH_INTERVAL: int = 60

# Authentication decorator
def require_api_key(f):
    def decorated_function(*args, **kwargs):
        api_key = request.args.get('api_key')
        if not api_key or api_key != API_KEY:
            abort(401, description="Unauthorized: Invalid API key")
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Validate container name
def validate_container_name(name: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_-]{1,64}$', name))

# LXC command execution (enhanced with better signal handling and logging)
def execute_lxc(full_command: str, timeout: int = 120) -> Dict[str, Any]:
    logger.info(f"Executing LXC command: {full_command}")
    try:
        cmd = shlex.split(full_command)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            preexec_fn=os.setsid
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            stdout = stdout.strip() if stdout else ""
            stderr = stderr.strip() if stderr else ""
            logger.info(f"LXC command completed: returncode={proc.returncode}")
            return {
                "returncode": proc.returncode,
                "stdout": stdout,
                "stderr": stderr
            }
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)  # Improved kill group
            proc.wait()
            logger.warning(f"LXC command timed out: {full_command}")
            return {"returncode": 124, "stdout": "", "stderr": "Command timed out"}
    except Exception as e:
        logger.error(f"LXC execution failed: {full_command} - {str(e)}")
        return {"returncode": 1, "stdout": "", "stderr": str(e)}

# Enhanced host resource functions
def get_host_cpu_usage() -> float:
    try:
        if shutil.which("mpstat"):
            result = subprocess.run(['mpstat', '1', '1'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                output = result.stdout
                for line in output.split('\n'):
                    if 'all' in line and '%' in line:
                        parts = line.split()
                        if len(parts) > 1:
                            idle = float(parts[-1].rstrip('%'))
                            return round(100.0 - idle, 1)
        # Fallback to top
        result = subprocess.run(['top', '-bn1'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            output = result.stdout
            for line in output.splitlines():
                if '%Cpu(s):' in line:
                    parts = line.split()
                    if len(parts) >= 16:
                        us = float(parts[1].rstrip(','))
                        sy = float(parts[3].rstrip(','))
                        ni = float(parts[5].rstrip(','))
                        wa = float(parts[9].rstrip(','))
                        hi = float(parts[11].rstrip(','))
                        si = float(parts[13].rstrip(','))
                        st = float(parts[15].rstrip(','))
                        usage = us + sy + ni + wa + hi + si + st
                        return round(usage, 1)
        return 0.0
    except Exception as e:
        logger.error(f"Error getting host CPU usage: {e}")
        return 0.0

def get_host_ram_usage() -> float:
    try:
        result = subprocess.run(['free', '-m'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                mem = lines[1].split()
                if len(mem) >= 3:
                    total = int(mem[1])
                    used = int(mem[2])
                    return round((used / total * 100), 1) if total > 0 else 0.0
        return 0.0
    except Exception as e:
        logger.error(f"Error getting host RAM usage: {e}")
        return 0.0

def get_host_disk_usage() -> str:
    try:
        result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 6 and parts[5] == '/':
                        used = parts[2]
                        size = parts[1]
                        perc = parts[4]
                        return f"{used}/{size} ({perc})"
        return "Unknown"
    except Exception as e:
        logger.error(f"Error getting host disk usage: {e}")
        return "Unknown"

def get_host_uptime() -> str:
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
        return result.stdout.strip() if result.returncode == 0 else "Unknown"
    except Exception as e:
        logger.error(f"Error getting host uptime: {e}")
        return "Unknown"

def get_host_stats() -> Dict[str, Any]:
    return {
        "cpu": get_host_cpu_usage(),
        "ram": get_host_ram_usage(),
        "disk": get_host_disk_usage(),
        "uptime": get_host_uptime()
    }

# Enhanced container stats (fallback to basic if advanced fails)
def get_container_status_local(container_name: str) -> str:
    try:
        result = subprocess.run(
            ["lxc", "info", container_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            output = result.stdout
            for line in output.splitlines():
                if line.startswith("Status: "):
                    return line.split(": ", 1)[1].strip().lower()
        return "unknown"
    except Exception:
        return "unknown"

def get_container_cpu_pct_local(container_name: str) -> float:
    try:
        # Only exec if running
        status = get_container_status_local(container_name)
        if status != "running":
            return 0.0
        result = subprocess.run(
            ["lxc", "exec", container_name, "--", "top", "-bn1"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            output = result.stdout
            for line in output.splitlines():
                if '%Cpu(s):' in line:
                    parts = line.split()
                    if len(parts) >= 16:
                        us = float(parts[1].rstrip(','))
                        sy = float(parts[3].rstrip(','))
                        ni = float(parts[5].rstrip(','))
                        wa = float(parts[9].rstrip(','))
                        hi = float(parts[11].rstrip(','))
                        si = float(parts[13].rstrip(','))
                        st = float(parts[15].rstrip(','))
                        return round(us + sy + ni + wa + hi + si + st, 1)
        return 0.0
    except Exception as e:
        logger.error(f"Error getting container CPU for {container_name}: {e}")
        return 0.0

def get_container_ram_local(container_name: str) -> Dict[str, Any]:
    try:
        status = get_container_status_local(container_name)
        if status != "running":
            return {'used': 0, 'total': 0, 'pct': 0.0}
        result = subprocess.run(
            ["lxc", "exec", container_name, "--", "free", "-m"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 3:
                    total = int(parts[1])
                    used = int(parts[2])
                    pct = round((used / total * 100), 1) if total > 0 else 0.0
                    return {'used': used, 'total': total, 'pct': pct}
        return {'used': 0, 'total': 0, 'pct': 0.0}
    except Exception as e:
        logger.error(f"Error getting container RAM for {container_name}: {e}")
        return {'used': 0, 'total': 0, 'pct': 0.0}

def get_container_disk_local(container_name: str) -> str:
    try:
        status = get_container_status_local(container_name)
        if status != "running":
            return "Stopped"
        result = subprocess.run(
            ["lxc", "exec", container_name, "--", "df", "-h", "/"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 6 and parts[5] == '/':
                        used = parts[2]
                        size = parts[1]
                        perc = parts[4]
                        return f"{used}/{size} ({perc})"
        return "Unknown"
    except Exception as e:
        logger.error(f"Error getting container disk for {container_name}: {e}")
        return "Unknown"

def get_container_uptime_local(container_name: str) -> str:
    try:
        status = get_container_status_local(container_name)
        if status != "running":
            return "Stopped"
        result = subprocess.run(
            ["lxc", "exec", container_name, "--", "uptime"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else "Unknown"
    except Exception as e:
        logger.error(f"Error getting container uptime for {container_name}: {e}")
        return "Unknown"

def get_container_stats(container_name: str) -> Dict[str, Any]:
    status = get_container_status_local(container_name)
    cpu = get_container_cpu_pct_local(container_name)
    ram = get_container_ram_local(container_name)
    disk = get_container_disk_local(container_name)
    uptime = get_container_uptime_local(container_name)
    return {"status": status, "cpu": cpu, "ram": ram, "disk": disk, "uptime": uptime}

# List containers (improved with JSON format for better reliability)
def list_containers() -> list:
    try:
        result = subprocess.run(["lxc", "list", "--format", "json"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return [c['name'] for c in data]
        # Fallback to lxc-ls
        result = subprocess.run(["lxc-ls", "-1"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return [c.strip() for c in result.stdout.splitlines() if c.strip()]
        return []
    except Exception as e:
        logger.error(f"Error listing containers: {e}")
        return []

# Container action helper
def container_action(container: str, action: str) -> bool:
    try:
        cmd = ["lxc", action, container]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        success = result.returncode == 0
        if success:
            logger.info(f"Container {action}d: {container}")
        else:
            logger.warning(f"Failed to {action} container {container}: {result.stderr}")
        return success
    except Exception as e:
        logger.error(f"Error in container {action}: {container} - {e}")
        return False

# New: Reinstall container (stop, destroy, recreate with template)
def reinstall_container(container: str, template: str = "") -> Dict[str, Any]:
    if not validate_container_name(container):
        return {"success": False, "message": "Invalid container name"}
    
    status = get_container_status_local(container)
    if status == "running":
        if not container_action(container, 'stop'):
            return {"success": False, "message": "Failed to stop container"}
    
    result = execute_lxc(f"lxc-destroy -n {container} -f")
    if result['returncode'] != 0:
        return {"success": False, "message": f"Failed to destroy container: {result['stderr']}"}
    
    create_cmd = f"lxc-create -n {container}"
    if template:
        create_cmd += f" {template}"
    else:
        create_cmd += f" {DEFAULT_TEMPLATE}"
    
    result = execute_lxc(create_cmd, timeout=600)  # Longer timeout for downloads/installs
    if result['returncode'] != 0:
        return {"success": False, "message": f"Failed to create container: {result['stderr']}"}
    
    return {"success": True, "message": "Container reinstalled successfully"}

# API Endpoints
@app.route('/api/ping', methods=['GET'])
@require_api_key
def api_ping():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()}), 200

@app.route('/api/execute', methods=['POST'])
@require_api_key
def api_execute():
    try:
        data = request.get_json()
        if not data or 'command' not in data:
            return jsonify({"error": "Missing 'command' in JSON body"}), 400
        full_command = data['command']
        timeout = data.get('timeout', 120)
        result = execute_lxc(full_command, timeout=timeout)
        return jsonify(result), 200 if result["returncode"] == 0 else 500
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON body"}), 400
    except Exception as e:
        logger.error(f"Execute API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_host_stats', methods=['GET'])
@require_api_key
def api_get_host_stats():
    try:
        stats = get_host_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Host stats API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_container_stats', methods=['POST'])
@require_api_key
def api_get_container_stats():
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in JSON body"}), 400
        container_name = data['container']
        if not validate_container_name(container_name):
            return jsonify({"error": "Invalid container name"}), 400
        stats = get_container_stats(container_name)
        return jsonify(stats)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON body"}), 400
    except Exception as e:
        logger.error(f"Container stats API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/list_containers', methods=['GET'])
@require_api_key
def api_list_containers():
    try:
        containers = list_containers()
        statuses = {c: get_container_status_local(c) for c in containers}
        return jsonify({"containers": containers, "statuses": statuses})
    except Exception as e:
        logger.error(f"List containers API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/start_container', methods=['POST'])
@require_api_key
def api_start_container():
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in JSON body"}), 400
        container = data['container']
        if not validate_container_name(container):
            return jsonify({"error": "Invalid container name"}), 400
        success = container_action(container, 'start')
        return jsonify({"success": success, "status": get_container_status_local(container)})
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON body"}), 400
    except Exception as e:
        logger.error(f"Start container API error: {str(e)}")
        return jupytext({"error": str(e)}), 500

@app.route('/api/stop_container', methods=['POST'])
@require_api_key
def api_stop_container():
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in JSON body"}), 400
        container = data['container']
        if not validate_container_name(container):
            return jsonify({"error": "Invalid container name"}), 400
        success = container_action(container, 'stop')
        return jsonify({"success": success, "status": get_container_status_local(container)})
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON body"}), 400
    except Exception as e:
        logger.error(f"Stop container API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/restart_container', methods=['POST'])
@require_api_key
def api_restart_container():
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in JSON body"}), 400
        container = data['container']
        if not validate_container_name(container):
            return jsonify({"error": "Invalid container name"}), 400
        success = container_action(container, 'restart')
        return jsonify({"success": success, "status": get_container_status_local(container)})
    except json.JSONDecodeError:
        return jupytext({"error": "Invalid JSON body"}), 400
    except Exception as e:
        logger.error(f"Restart container API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# New endpoint for reinstall
@app.route('/api/reinstall_container', methods=['POST'])
@require_api_key
def api_reinstall_container():
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in JSON body"}), 400
        container = data['container']
        template = data.get('template', "")
        result = reinstall_container(container, template)
        return jsonify(result), 200 if result["success"] else 500
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON body"}), 400
    except Exception as e:
        logger.error(f"Reinstall container API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Enhanced health monitor thread (logs host stats periodically)
def health_monitor(interval: int = 60):
    logger.info(f"Health monitor started (interval: {interval}s)")
    while True:
        try:
            stats = get_host_stats()
            logger.info(
                f"Host Health: CPU {stats['cpu']:.1f}%, RAM {stats['ram']:.1f}%, "
                f"Disk {stats['disk']}, Uptime {stats['uptime']}"
            )
            time.sleep(interval)
        except Exception as e:
            logger.error(f"Health monitor error: {e}")
            time.sleep(interval)

if __name__ == '__main__':
    # Load .env first
    env_config = load_env()

    # Setup logging from .env
    log_level = env_config.get('LOG_LEVEL', 'INFO')
    setup_logging(log_level)

    # Argument parser (overrides .env)
    parser = argparse.ArgumentParser(description='Node Agent for VPS Management Bot (Upgraded)')
    parser.add_argument('--api_key', help='API Key for authentication (overrides .env)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on (default: 5000, overrides .env)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0, overrides .env)')
    parser.add_argument('--log_level', help='Log level (overrides .env)')
    args = parser.parse_args()

    # Apply overrides
    if args.log_level:
        setup_logging(args.log_level)  # Re-setup if overridden

    API_KEY = args.api_key or env_config.get('API_KEY')
    if not API_KEY:
        parser.error("API_KEY is required. Set it in .env or use --api_key")

    PORT = args.port or int(env_config.get('PORT', 5000))
    HOST = args.host or env_config.get('HOST', '0.0.0.0')
    DEFAULT_TEMPLATE = env_config.get('DEFAULT_TEMPLATE', DEFAULT_TEMPLATE)
    HEALTH_INTERVAL = int(env_config.get('HEALTH_INTERVAL', 60))

    logger.info(f"Starting Node Agent on {HOST}:{PORT} with API Key: {API_KEY[:8]}...")
    logger.info(f"Log Level: {log_level.upper()}")
    logger.info(f"Default Template: {DEFAULT_TEMPLATE}")
    logger.info(f"Health Interval: {HEALTH_INTERVAL}s")

    # Start health monitor thread (daemon)
    monitor_thread = threading.Thread(target=health_monitor, args=(HEALTH_INTERVAL,), daemon=True)
    monitor_thread.start()

    # Run Flask app
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
