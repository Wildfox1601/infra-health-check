# Infrastructure Health Check

A lightweight Python-based infrastructure monitoring and diagnostics tool for Linux systems.

The project performs basic infrastructure health checks across hosts and services, collects local system resource metrics, analyzes Linux authentication logs, evaluates configurable thresholds, and generates human-readable and JSON reports.

## Features

- ICMP host reachability checks
- TCP service and port availability checks
- Concurrent network checks using `ThreadPoolExecutor`
- CPU utilization monitoring
- Memory utilization monitoring
- Root filesystem disk utilization monitoring
- System uptime and load-average reporting
- Linux authentication log analysis
- Detection of failed SSH authentication attempts
- Detection of invalid-user login attempts
- Configurable warning and critical thresholds
- JSON configuration
- Human-readable terminal reports
- Timestamped JSON reports
- Verbose application logging
- Meaningful process exit codes for automation

## Project Structure

```text
infrastructure-health-check/
├── healthcheck.py
├── config.json
├── requirements.txt
├── reports/
└── README.md
```

### Files

| File | Purpose |
| --- | --- |
| `healthcheck.py` | Main monitoring and reporting application |
| `config.json` | Hosts, services, thresholds, and runtime settings |
| `requirements.txt` | Python dependency list |
| `reports/` | Generated JSON health reports |
| `README.md` | Project documentation |

## Requirements

- Linux system recommended
- Python 3.10+
- `ping` utility
- Access to Linux authentication logs for log analysis
- `psutil`

The tool can also run on other operating systems for the checks supported by those systems, but Linux is the primary target.

## Installation

Clone or create the project directory:

```bash
git clone <your-repository-url>
cd infrastructure-health-check
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

The monitoring targets are defined in `config.json`.

Example:

```json
{
    "hosts": [
        "127.0.0.1",
        "192.168.1.50",
        "192.168.1.51"
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
        },
        {
            "port": 443,
            "name": "HTTPS",
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
```

### Configuration Sections

#### `hosts`

List of hosts to check for ICMP reachability.

```json
"hosts": [
    "192.168.1.50",
    "192.168.1.51"
]
```

#### `ports`

TCP services to test.

```json
{
    "port": 22,
    "name": "SSH",
    "timeout": 2
}
```

The tool reports whether the TCP connection succeeds, is refused, or times out.

#### `thresholds`

Thresholds determine when local system metrics and authentication activity generate warnings or critical alerts.

Example:

```json
"cpu_warning": 70,
"cpu_critical": 90
```

#### `settings`

Controls runtime behavior such as:

- ICMP timeout
- Maximum concurrent workers
- Number of authentication-log lines to inspect
- Report output directory

## Usage

Basic health check:

```bash
python3 healthcheck.py
```

Enable verbose logging:

```bash
python3 healthcheck.py --verbose
```

Specify another configuration file:

```bash
python3 healthcheck.py --config config.json
```

Specify a report directory:

```bash
python3 healthcheck.py --output reports
```

Run without generating a JSON report:

```bash
python3 healthcheck.py --no-report
```

Display command-line help:

```bash
python3 healthcheck.py --help
```

## Example Output

```text
=================================================================
              INFRASTRUCTURE HEALTH REPORT
=================================================================

Timestamp       : 2026-09-18T15:12:42+00:00
Overall Status  : WARNING

HOST REACHABILITY
-----------------------------------------------------------------
127.0.0.1            UP             1.82 ms
192.168.1.50         UP             2.41 ms
192.168.1.51         DOWN           No response to ICMP ping

TCP SERVICES
-----------------------------------------------------------------
127.0.0.1        22     SSH          OPEN       0.31 ms
127.0.0.1        80     HTTP         CLOSED     -
192.168.1.50     22     SSH          OPEN       1.21 ms
192.168.1.50     80     HTTP         OPEN       1.44 ms

LOCAL SYSTEM
-----------------------------------------------------------------
Hostname        : linux-server
Platform        : Linux-6.x.x-x86_64
Uptime          : 2d 14h 32m
CPU Usage       : 21.4%
Memory Usage    : 47.8%
Disk Usage      : 63.2%
Load Average    : 0.42, 0.37, 0.31

AUTHENTICATION LOG ANALYSIS
-----------------------------------------------------------------
Log file        : /var/log/auth.log
Lines scanned   : 5000
Failed SSH      : 7
Invalid users   : 3
Auth failures   : 7

ALERTS
-----------------------------------------------------------------
[WARNING]  Elevated failed SSH attempts: 7

=================================================================
```

## What the Tool Checks

### 1. Host Reachability

The tool invokes the system `ping` utility to determine whether configured hosts respond to ICMP echo requests.

The result includes:

- Host address
- Reachability state
- Approximate response time
- Error information when unavailable

### 2. TCP Service Availability

The tool uses Python's `socket` module to attempt TCP connections to configured service ports.

For example:

```text
192.168.1.50:22
```

can be used to verify whether SSH is accepting TCP connections.

A service can therefore be distinguished from simple host reachability:

```text
ICMP reachable ≠ TCP service available
```

### 3. System Resource Monitoring

Using `psutil`, the tool collects:

- CPU utilization
- Memory utilization
- Root filesystem utilization
- System uptime
- Load average
- Hostname
- Platform information

### 4. Authentication Log Analysis

On Linux systems, the tool looks for:

```text
/var/log/auth.log
```

or:

```text
/var/log/secure
```

It analyzes recent log entries for:

- Failed password attempts
- Invalid users
- Authentication failures

This provides a basic view of authentication-related activity without requiring a separate SIEM.

### 5. Threshold Evaluation

Resource and authentication metrics are compared against configurable thresholds.

Example:

```text
CPU < 70%       → normal
CPU 70–89%      → warning
CPU >= 90%      → critical
```

The exact thresholds are controlled through `config.json`.

## Architecture

```text
                    Health Check Application
                              |
             +----------------+----------------+
             |                |                |
             v                v                v
       Host Checks       Service Checks    Local System
             |                |                |
          ICMP Ping        TCP Socket       psutil
             |                |                |
             +----------------+----------------+
                              |
                              v
                    Authentication Logs
                              |
                              v
                    Threshold Evaluation
                              |
                              v
                     Health Status
                         /       \
                        /         \
                       v           v
                 Terminal       JSON Report
                   Report
```

## Concurrency

Network checks use Python's:

```python
ThreadPoolExecutor
```

This allows multiple hosts and services to be checked concurrently rather than waiting for each network operation sequentially.

This is useful when the number of monitored hosts increases because network operations are primarily I/O-bound.

The maximum number of worker threads is configurable:

```json
"max_workers": 10
```

## Exit Codes

The application returns different exit codes depending on infrastructure health:

| Exit Code | Meaning |
| --- | --- |
| `0` | Healthy |
| `1` | Warning or execution error |
| `2` | Critical condition |
| `130` | Interrupted by user |

These exit codes allow the script to be integrated with automation tools, cron jobs, CI/CD pipelines, or external monitoring systems.

Example:

```bash
python3 healthcheck.py
echo $?
```

## Running with Cron

The tool can be scheduled using cron.

Edit the user's crontab:

```bash
crontab -e
```

Example:

```text
*/10 * * * * /path/to/infrastructure-health-check/.venv/bin/python /path/to/infrastructure-health-check/healthcheck.py >> /path/to/infrastructure-health-check/healthcheck.log 2>&1
```

This runs the health check every 10 minutes.

## Security Considerations

This project is intended for systems and networks that you own or are authorized to monitor.

The tool:

- Performs ICMP reachability checks
- Attempts TCP connections only to explicitly configured ports
- Reads local authentication logs
- Does not perform vulnerability exploitation
- Does not attempt password guessing
- Does not modify remote systems

Run it with only the privileges required for the checks you need.

Authentication log access may require elevated privileges depending on the Linux distribution and log permissions.

For example:

```bash
sudo python3 healthcheck.py
```

should only be used when necessary.

## Limitations

This is intentionally a lightweight monitoring and diagnostics tool rather than a full monitoring platform.

Current limitations include:

- No persistent time-series database
- No web dashboard
- No alert delivery through email or messaging services
- ICMP checks depend on the system `ping` utility
- Authentication-log format varies between Linux distributions
- TCP connectivity does not guarantee that an application-layer service is functioning correctly
- Disk monitoring currently focuses on the root filesystem
- Authentication analysis is based on simple log-pattern matching

## Possible Future Improvements

Potential extensions include:

- YAML configuration support
- ICMP latency statistics over time
- HTTP health checks
- DNS resolution checks
- SSH service-specific checks
- Network interface monitoring
- Per-filesystem disk monitoring
- CSV report generation
- SQLite time-series storage
- Prometheus metrics endpoint
- Grafana dashboard
- Email or webhook alerts
- Systemd service integration
- Docker deployment
- Multi-server remote monitoring
- Historical health trends

## Skills Demonstrated

This project demonstrates practical knowledge of:

- Python
- Linux system administration
- TCP/IP networking
- ICMP
- TCP sockets
- Service availability monitoring
- Linux authentication logs
- Resource monitoring
- JSON configuration
- Concurrent programming
- Exception handling
- CLI application development
- Logging
- Automation
- Infrastructure troubleshooting

## Resume Description

A concise resume-ready description for this project:

> **Python Infrastructure Health-Check Automation** — Developed a Python CLI utility to monitor host reachability and TCP service availability, collect CPU/memory/disk metrics, analyze Linux authentication logs, evaluate configurable health thresholds, and generate automated JSON status reports using concurrent network checks.

## License

This project is intended as a personal learning and portfolio project.