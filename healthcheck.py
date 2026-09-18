#!/usr/bin/env python3

"""
Infrastructure Health Check
----------------------------

A lightweight infrastructure monitoring tool for Linux systems.

Features:
    - ICMP host reachability checks
    - TCP service/port availability checks
    - CPU, memory, disk and uptime monitoring
    - Linux authentication log analysis
    - Configurable warning/critical thresholds
    - Concurrent network checks
    - Human-readable terminal report
    - JSON report generation
    - Structured application logging

Author: Tarun M
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import socket
import subprocess
import sys
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError:
    print("ERROR: psutil is not installed.")
    print("Install it with: python3 -m pip install psutil")
    sys.exit(1)


# ============================================================
# Configuration
# ============================================================

DEFAULT_CONFIG = {
    "hosts": [
        "127.0.0.1"
    ],
    "ports": [
        {
            "port": 22,
            "name": "SSH",
            "timeout": 2
        },
        {
            "port": 80,
            "name": "HTTP",
            "timeout": 2
        }
    ],
    "thresholds": {
        "cpu_warning": 70,
        "cpu_critical": 90,
        "memory_warning": 75,
        "memory_critical": 90,
        "disk_warning": 75,
        "disk_critical": 90,
        "failed_ssh_warning": 5,
        "failed_ssh_critical": 20
    },
    "settings": {
        "ping_timeout": 2,
        "max_workers": 10,
        "log_lines": 5000,
        "report_directory": "reports"
    }
}


# ============================================================
# Data Models
# ============================================================

@dataclass
class HostResult:
    host: str
    reachable: bool
    latency_ms: float | None = None
    error: str | None = None


@dataclass
class PortResult:
    host: str
    port: int
    service: str
    open: bool
    latency_ms: float | None = None
    error: str | None = None


@dataclass
class SystemMetrics:
    hostname: str
    platform: str
    uptime_seconds: float
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    load_average: tuple[float, float, float] | None = None


@dataclass
class LogAnalysis:
    log_file: str
    lines_scanned: int
    failed_ssh_attempts: int
    invalid_user_attempts: int
    authentication_failures: int
    readable: bool
    error: str | None = None


@dataclass
class HealthReport:
    timestamp: str
    overall_status: str
    hosts: list[HostResult] = field(default_factory=list)
    services: list[PortResult] = field(default_factory=list)
    system: SystemMetrics | None = None
    logs: LogAnalysis | None = None
    warnings: list[str] = field(default_factory=list)
    critical: list[str] = field(default_factory=list)


# ============================================================
# Logging
# ============================================================

def setup_logging(verbose: bool = False) -> None:
    """Configure application logging."""

    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


logger = logging.getLogger(__name__)


# ============================================================
# Utility Functions
# ============================================================

def load_config(path: Path) -> dict[str, Any]:
    """Load JSON configuration."""

    if not path.exists():
        logger.warning(
            "Configuration file %s does not exist. Using defaults.",
            path
        )
        return DEFAULT_CONFIG.copy()

    try:
        with path.open("r", encoding="utf-8") as file:
            config = json.load(file)

        logger.info("Loaded configuration from %s", path)
        return config

    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON configuration: %s", exc)
        sys.exit(1)

    except OSError as exc:
        logger.error("Unable to read configuration: %s", exc)
        sys.exit(1)


def timestamp() -> str:
    """Return an ISO-8601 UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


# ============================================================
# Host Reachability
# ============================================================

def check_host(host: str, timeout: int = 2) -> HostResult:
    """
    Check whether a host responds to ICMP ping.

    Uses the system ping command so the script does not require
    raw socket privileges.
    """

    logger.debug("Checking host reachability: %s", host)

    system = platform.system().lower()

    if system == "windows":
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            str(timeout * 1000),
            host
        ]
    else:
        command = [
            "ping",
            "-c",
            "1",
            "-W",
            str(timeout),
            host
        ]

    start = time.perf_counter()

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
            check=False
        )

        latency = (time.perf_counter() - start) * 1000

        if result.returncode == 0:
            logger.debug(
                "Host %s is reachable (%.2f ms)",
                host,
                latency
            )

            return HostResult(
                host=host,
                reachable=True,
                latency_ms=round(latency, 2)
            )

        logger.warning("Host %s is unreachable", host)

        return HostResult(
            host=host,
            reachable=False,
            error="No response to ICMP ping"
        )

    except subprocess.TimeoutExpired:
        return HostResult(
            host=host,
            reachable=False,
            error="Ping timeout"
        )

    except FileNotFoundError:
        return HostResult(
            host=host,
            reachable=False,
            error="ping command not found"
        )

    except OSError as exc:
        return HostResult(
            host=host,
            reachable=False,
            error=str(exc)
        )


# ============================================================
# TCP Service Checks
# ============================================================

def check_port(
    host: str,
    port: int,
    service: str,
    timeout: int = 2
) -> PortResult:
    """Check TCP connectivity to a service."""

    logger.debug(
        "Checking %s:%d (%s)",
        host,
        port,
        service
    )

    start = time.perf_counter()

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout
        ):
            latency = (time.perf_counter() - start) * 1000

            return PortResult(
                host=host,
                port=port,
                service=service,
                open=True,
                latency_ms=round(latency, 2)
            )

    except socket.timeout:
        return PortResult(
            host=host,
            port=port,
            service=service,
            open=False,
            error="Connection timeout"
        )

    except ConnectionRefusedError:
        return PortResult(
            host=host,
            port=port,
            service=service,
            open=False,
            error="Connection refused"
        )

    except OSError as exc:
        return PortResult(
            host=host,
            port=port,
            service=service,
            open=False,
            error=str(exc)
        )


def check_services(
    hosts: list[str],
    ports: list[dict[str, Any]],
    max_workers: int
) -> list[PortResult]:
    """Run TCP checks concurrently."""

    results: list[PortResult] = []

    tasks = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        for host in hosts:
            for service in ports:

                tasks.append(
                    executor.submit(
                        check_port,
                        host,
                        int(service["port"]),
                        service.get("name", "Unknown"),
                        int(service.get("timeout", 2))
                    )
                )

        for future in as_completed(tasks):
            results.append(future.result())

    return sorted(
        results,
        key=lambda result: (
            result.host,
            result.port
        )
    )


# ============================================================
# System Monitoring
# ============================================================

def collect_system_metrics() -> SystemMetrics:
    """Collect local Linux system metrics."""

    logger.debug("Collecting local system metrics")

    uptime = time.time() - psutil.boot_time()

    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    load_average = None

    try:
        load_average = psutil.getloadavg()
    except (AttributeError, OSError):
        pass

    return SystemMetrics(
        hostname=socket.gethostname(),
        platform=platform.platform(),
        uptime_seconds=round(uptime, 2),
        cpu_percent=round(psutil.cpu_percent(interval=1), 2),
        memory_percent=round(memory.percent, 2),
        disk_percent=round(disk.percent, 2),
        load_average=load_average
    )


# ============================================================
# Linux Log Analysis
# ============================================================

def find_auth_log() -> Path | None:
    """Find the authentication log used by the system."""

    candidates = [
        Path("/var/log/auth.log"),
        Path("/var/log/secure")
    ]

    for path in candidates:
        if path.exists():
            return path

    return None


def analyze_auth_log(
    max_lines: int = 5000
) -> LogAnalysis:
    """
    Analyze Linux authentication logs.

    Looks for:
        - Failed password attempts
        - Invalid users
        - Authentication failures
    """

    log_path = find_auth_log()

    if log_path is None:
        return LogAnalysis(
            log_file="Not found",
            lines_scanned=0,
            failed_ssh_attempts=0,
            invalid_user_attempts=0,
            authentication_failures=0,
            readable=False,
            error="Authentication log not found"
        )

    failed_ssh = 0
    invalid_users = 0
    auth_failures = 0
    lines_scanned = 0

    try:
        with log_path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            # Read only the last N lines to avoid processing
            # enormous log files.
            lines = file.readlines()[-max_lines:]

            for line in lines:

                lines_scanned += 1

                lower = line.lower()

                if "failed password" in lower:
                    failed_ssh += 1

                if "invalid user" in lower:
                    invalid_users += 1

                if "authentication failure" in lower:
                    auth_failures += 1

        return LogAnalysis(
            log_file=str(log_path),
            lines_scanned=lines_scanned,
            failed_ssh_attempts=failed_ssh,
            invalid_user_attempts=invalid_users,
            authentication_failures=auth_failures,
            readable=True
        )

    except PermissionError:
        return LogAnalysis(
            log_file=str(log_path),
            lines_scanned=0,
            failed_ssh_attempts=0,
            invalid_user_attempts=0,
            authentication_failures=0,
            readable=False,
            error="Permission denied"
        )

    except OSError as exc:
        return LogAnalysis(
            log_file=str(log_path),
            lines_scanned=0,
            failed_ssh_attempts=0,
            invalid_user_attempts=0,
            authentication_failures=0,
            readable=False,
            error=str(exc)
        )


# ============================================================
# Threshold Evaluation
# ============================================================

def evaluate_thresholds(
    system: SystemMetrics,
    logs: LogAnalysis,
    thresholds: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """Generate warning and critical conditions."""

    warnings: list[str] = []
    critical: list[str] = []

    cpu = system.cpu_percent

    if cpu >= thresholds["cpu_critical"]:
        critical.append(
            f"CPU usage is critical: {cpu}%"
        )
    elif cpu >= thresholds["cpu_warning"]:
        warnings.append(
            f"CPU usage is high: {cpu}%"
        )

    memory = system.memory_percent

    if memory >= thresholds["memory_critical"]:
        critical.append(
            f"Memory usage is critical: {memory}%"
        )
    elif memory >= thresholds["memory_warning"]:
        warnings.append(
            f"Memory usage is high: {memory}%"
        )

    disk = system.disk_percent

    if disk >= thresholds["disk_critical"]:
        critical.append(
            f"Disk usage is critical: {disk}%"
        )
    elif disk >= thresholds["disk_warning"]:
        warnings.append(
            f"Disk usage is high: {disk}%"
        )

    failed_ssh = logs.failed_ssh_attempts

    if failed_ssh >= thresholds["failed_ssh_critical"]:
        critical.append(
            f"High number of failed SSH attempts: {failed_ssh}"
        )
    elif failed_ssh >= thresholds["failed_ssh_warning"]:
        warnings.append(
            f"Elevated failed SSH attempts: {failed_ssh}"
        )

    return warnings, critical


# ============================================================
# Report Generation
# ============================================================

def determine_overall_status(
    warnings: list[str],
    critical: list[str],
    hosts: list[HostResult],
    services: list[PortResult]
) -> str:
    """Determine overall infrastructure health."""

    if critical:
        return "CRITICAL"

    if warnings:
        return "WARNING"

    if any(not host.reachable for host in hosts):
        return "WARNING"

    # A closed port isn't automatically a failure because
    # some services may intentionally be disabled.
    return "HEALTHY"


def create_report(config: dict[str, Any]) -> HealthReport:
    """Run all health checks and construct the report."""

    settings = config["settings"]

    hosts = config["hosts"]
    ports = config["ports"]

    logger.info("Starting infrastructure health check")

    # Host checks concurrently
    host_results: list[HostResult] = []

    with ThreadPoolExecutor(
        max_workers=settings["max_workers"]
    ) as executor:

        futures = {
            executor.submit(
                check_host,
                host,
                settings["ping_timeout"]
            ): host
            for host in hosts
        }

        for future in as_completed(futures):
            host_results.append(future.result())

    host_results.sort(key=lambda result: result.host)

    # Service checks
    service_results = check_services(
        hosts,
        ports,
        settings["max_workers"]
    )

    # Local system metrics
    system_metrics = collect_system_metrics()

    # Authentication log analysis
    log_analysis = analyze_auth_log(
        settings["log_lines"]
    )

    # Threshold evaluation
    warnings, critical = evaluate_thresholds(
        system_metrics,
        log_analysis,
        config["thresholds"]
    )

    overall_status = determine_overall_status(
        warnings,
        critical,
        host_results,
        service_results
    )

    logger.info(
        "Health check completed: %s",
        overall_status
    )

    return HealthReport(
        timestamp=timestamp(),
        overall_status=overall_status,
        hosts=host_results,
        services=service_results,
        system=system_metrics,
        logs=log_analysis,
        warnings=warnings,
        critical=critical
    )


# ============================================================
# Terminal Report
# ============================================================

def format_uptime(seconds: float) -> str:
    """Convert seconds into a readable uptime."""

    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)

    return f"{days}d {hours}h {minutes}m"


def print_report(report: HealthReport) -> None:
    """Display a human-readable report."""

    print()
    print("=" * 65)
    print("              INFRASTRUCTURE HEALTH REPORT")
    print("=" * 65)

    print(f"Timestamp       : {report.timestamp}")
    print(f"Overall Status  : {report.overall_status}")

    # Hosts
    print()
    print("HOST REACHABILITY")
    print("-" * 65)

    for result in report.hosts:

        if result.reachable:
            print(
                f"{result.host:<20} UP       "
                f"{result.latency_ms:>8.2f} ms"
            )
        else:
            print(
                f"{result.host:<20} DOWN     "
                f"{result.error}"
            )

    # Services
    print()
    print("TCP SERVICES")
    print("-" * 65)

    for result in report.services:

        state = "OPEN" if result.open else "CLOSED"

        latency = (
            f"{result.latency_ms:.2f} ms"
            if result.latency_ms is not None
            else "-"
        )

        print(
            f"{result.host:<16} "
            f"{result.port:<6} "
            f"{result.service:<12} "
            f"{state:<8} "
            f"{latency}"
        )

    # System
    if report.system:

        system = report.system

        print()
        print("LOCAL SYSTEM")
        print("-" * 65)

        print(f"Hostname        : {system.hostname}")
        print(f"Platform        : {system.platform}")
        print(f"Uptime          : {format_uptime(system.uptime_seconds)}")
        print(f"CPU Usage       : {system.cpu_percent}%")
        print(f"Memory Usage    : {system.memory_percent}%")
        print(f"Disk Usage      : {system.disk_percent}%")

        if system.load_average:
            print(
                "Load Average    : "
                f"{system.load_average[0]:.2f}, "
                f"{system.load_average[1]:.2f}, "
                f"{system.load_average[2]:.2f}"
            )

    # Logs
    if report.logs:

        logs = report.logs

        print()
        print("AUTHENTICATION LOG ANALYSIS")
        print("-" * 65)

        print(f"Log file        : {logs.log_file}")
        print(f"Lines scanned   : {logs.lines_scanned}")
        print(f"Failed SSH      : {logs.failed_ssh_attempts}")
        print(f"Invalid users   : {logs.invalid_user_attempts}")
        print(f"Auth failures   : {logs.authentication_failures}")

        if logs.error:
            print(f"Error           : {logs.error}")

    # Alerts
    if report.warnings or report.critical:

        print()
        print("ALERTS")
        print("-" * 65)

        for item in report.critical:
            print(f"[CRITICAL] {item}")

        for item in report.warnings:
            print(f"[WARNING]  {item}")

    print()
    print("=" * 65)


# ============================================================
# JSON Export
# ============================================================

def save_json_report(
    report: HealthReport,
    directory: Path
) -> Path:
    """Save report as JSON."""

    directory.mkdir(
        parents=True,
        exist_ok=True
    )

    filename = (
        datetime.now().strftime(
            "health-report-%Y%m%d-%H%M%S.json"
        )
    )

    path = directory / filename

    with path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            asdict(report),
            file,
            indent=4
        )

    logger.info("Report saved to %s", path)

    return path


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "Linux infrastructure health monitoring "
            "and diagnostics tool."
        )
    )

    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path("config.json"),
        help="Path to JSON configuration file."
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Directory for generated reports."
    )

    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Do not save a JSON report."
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging."
    )

    return parser.parse_args()


# ============================================================
# Main
# ============================================================

def main() -> int:

    args = parse_arguments()

    setup_logging(args.verbose)

    config = load_config(args.config)

    try:
        report = create_report(config)

        print_report(report)

        if not args.no_report:

            directory = (
                args.output
                if args.output
                else Path(
                    config["settings"]["report_directory"]
                )
            )

            save_json_report(
                report,
                directory
            )

        # Exit codes make the script useful for automation.
        if report.overall_status == "CRITICAL":
            return 2

        if report.overall_status == "WARNING":
            return 1

        return 0

    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        return 130

    except Exception:
        logger.exception(
            "Unexpected error during health check."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())