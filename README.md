# Blackbox Exporter Installation Guide

Blackbox Exporter is a Prometheus exporter that allows blackbox probing of endpoints over HTTP, HTTPS, DNS, TCP, ICMP and gRPC. It's essential for monitoring external services and endpoints from a user perspective.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- Linux-based operating system
- Prometheus server installed and configured
- Basic understanding of Prometheus and monitoring concepts
- Network access to targets you want to probe
- For systemd service: systemd-based Linux distribution


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### Binary Installation

1. **Download the latest release**:
```bash
# Check latest version at https://github.com/prometheus/blackbox_exporter/releases
VERSION="0.24.0"
ARCH="linux-amd64"

# Download binary
wget https://github.com/prometheus/blackbox_exporter/releases/download/v${VERSION}/blackbox_exporter-${VERSION}.${ARCH}.tar.gz

# Extract archive
tar xvfz blackbox_exporter-${VERSION}.${ARCH}.tar.gz

# Move binary to system path
sudo mv blackbox_exporter-${VERSION}.${ARCH}/blackbox_exporter /usr/local/bin/
sudo chown root:root /usr/local/bin/blackbox_exporter
sudo chmod +x /usr/local/bin/blackbox_exporter
```

2. **Create user and directories**:
```bash
# Create system user
sudo useradd --no-create-home --shell /bin/false blackbox_exporter

# Create config directory
sudo mkdir -p /etc/blackbox_exporter
sudo chown blackbox_exporter:blackbox_exporter /etc/blackbox_exporter
```

### Docker Installation

```bash
# Run with Docker
docker run -d \
  --name blackbox_exporter \
  -p 9115:9115 \
  -v /path/to/blackbox.yml:/config/blackbox.yml \
  prom/blackbox-exporter:latest \
  --config.file=/config/blackbox.yml
```

### Package Manager Installation

**Ubuntu/Debian**:
```bash
# Not available in default repos, use binary installation
```

**RHEL/CentOS/Fedora**:
```bash
# Not available in default repos, use binary installation
```

**Arch Linux**:
```bash
sudo pacman -S prometheus-blackbox-exporter
```

## 4. Configuration

### Basic Configuration

Create `/etc/blackbox_exporter/blackbox.yml`:
```yaml
modules:
  # HTTP/HTTPS probe
  http_2xx:
    prober: http
    timeout: 5s
    http:
      preferred_ip_protocol: "ip4"
      ip_protocol_fallback: false
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      valid_status_codes: []  # Defaults to 2xx
      method: GET
      follow_redirects: true
      fail_if_ssl: false
      fail_if_not_ssl: false
      tls_config:
        insecure_skip_verify: false

  # HTTPS with specific status codes
  http_post_2xx:
    prober: http
    timeout: 5s
    http:
      method: POST
      headers:
        Content-Type: application/json
      body: '{"test": "data"}'
      valid_status_codes: [200, 201, 202]

  # TCP probe
  tcp_connect:
    prober: tcp
    timeout: 5s

  # ICMP ping probe
  icmp:
    prober: icmp
    timeout: 5s
    icmp:
      preferred_ip_protocol: "ip4"

  # DNS probe
  dns_udp:
    prober: dns
    timeout: 5s
    dns:
      preferred_ip_protocol: "ip4"
      query_name: "www.example.com"
      query_type: "A"
      valid_rcodes:
        - NOERROR

  # SSL certificate check
  http_ssl_cert:
    prober: http
    timeout: 5s
    http:
      method: GET
      fail_if_ssl: false
      fail_if_not_ssl: true
      tls_config:
        insecure_skip_verify: false
```

### Advanced Modules

```yaml
modules:
  # HTTP with authentication
  http_basic_auth:
    prober: http
    timeout: 5s
    http:
      basic_auth:
        username: "monitoring"
        password: "secure_password"
      valid_status_codes: [200]

  # HTTP with custom headers
  http_custom_headers:
    prober: http
    timeout: 5s
    http:
      headers:
        X-API-Key: "your-api-key"
        Accept: "application/json"

  # gRPC probe
  grpc:
    prober: grpc
    timeout: 5s
    grpc:
      tls: true
      tls_config:
        insecure_skip_verify: false

  # TCP with TLS
  tcp_tls:
    prober: tcp
    timeout: 5s
    tcp:
      tls: true
      tls_config:
        insecure_skip_verify: false

  # HTTP with regex matching
  http_content_match:
    prober: http
    timeout: 5s
    http:
      valid_status_codes: [200]
      fail_if_body_not_matches_regexp:
        - "Welcome.*"
      fail_if_body_matches_regexp:
        - "Error.*"

  # Slow HTTP probe
  http_slow:
    prober: http
    timeout: 30s
    http:
      method: GET
```

### Systemd Service

Create `/etc/systemd/system/blackbox_exporter.service`:
```ini
[Unit]
Description=Blackbox Exporter
After=network-online.target

[Service]
Type=simple
User=blackbox_exporter
Group=blackbox_exporter
ExecStart=/usr/local/bin/blackbox_exporter \
  --config.file=/etc/blackbox_exporter/blackbox.yml \
  --web.listen-address=:9115

Restart=on-failure
RestartSec=5s

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/blackbox_exporter

# Required for ICMP probes
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

Start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable blackbox_exporter
sudo systemctl start blackbox_exporter
sudo systemctl status blackbox_exporter
```

## Prometheus Configuration

### Configure Prometheus Scrape Jobs

Add to `prometheus.yml`:
```yaml
scrape_configs:
  # Blackbox exporter itself
  - job_name: 'blackbox'
    static_configs:
      - targets: ['localhost:9115']

  # HTTP/HTTPS monitoring
  - job_name: 'blackbox-http'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
        - https://example.com
        - https://api.example.com/health
        - http://internal-service:8080
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115

  # TCP port monitoring
  - job_name: 'blackbox-tcp'
    metrics_path: /probe
    params:
      module: [tcp_connect]
    static_configs:
      - targets:
        - database.example.com:5432
        - cache.example.com:6379
        - message-broker.example.com:5672
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115

  # ICMP ping monitoring
  - job_name: 'blackbox-icmp'
    metrics_path: /probe
    params:
      module: [icmp]
    static_configs:
      - targets:
        - gateway.example.com
        - dns1.example.com
        - dns2.example.com
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115

  # SSL certificate monitoring
  - job_name: 'blackbox-ssl'
    metrics_path: /probe
    params:
      module: [http_ssl_cert]
    static_configs:
      - targets:
        - https://secure.example.com
        - https://api.example.com
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115
```

### File-based Service Discovery

```yaml
scrape_configs:
  - job_name: 'blackbox-http-file-sd'
    metrics_path: /probe
    params:
      module: [http_2xx]
    file_sd_configs:
      - files:
        - '/etc/prometheus/blackbox-targets/*.yml'
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115
```

Target file `/etc/prometheus/blackbox-targets/web.yml`:
```yaml
- targets:
  - https://app1.example.com
  - https://app2.example.com
  labels:
    service: web
    env: production

- targets:
  - https://staging.example.com
  labels:
    service: web
    env: staging
```

## Alert Rules

Create `/etc/prometheus/alerts/blackbox.yml`:
```yaml
groups:
  - name: blackbox
    rules:
      # Website down
      - alert: WebsiteDown
        expr: probe_success{job="blackbox-http"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Website down (instance {{ $labels.instance }})"
          description: "Website {{ $labels.instance }} has been down for more than 5 minutes."

      # SSL certificate expiry
      - alert: SSLCertificateExpiringSoon
        expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 30
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "SSL certificate expiring soon (instance {{ $labels.instance }})"
          description: "SSL certificate for {{ $labels.instance }} expires in less than 30 days."

      - alert: SSLCertificateExpired
        expr: probe_ssl_earliest_cert_expiry - time() < 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "SSL certificate expired (instance {{ $labels.instance }})"
          description: "SSL certificate for {{ $labels.instance }} has expired."

      # Slow response time
      - alert: SlowResponseTime
        expr: probe_http_duration_seconds{job="blackbox-http"} > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow HTTP response (instance {{ $labels.instance }})"
          description: "HTTP response time for {{ $labels.instance }} is {{ $value }}s (> 2s)."

      # TCP port down
      - alert: TCPPortDown
        expr: probe_success{job="blackbox-tcp"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "TCP port down (instance {{ $labels.instance }})"
          description: "TCP port {{ $labels.instance }} has been down for more than 5 minutes."

      # High packet loss
      - alert: HighPacketLoss
        expr: (1 - avg_over_time(probe_success{job="blackbox-icmp"}[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High packet loss (instance {{ $labels.instance }})"
          description: "Packet loss for {{ $labels.instance }} is {{ $value | humanizePercentage }}."
```

## Grafana Dashboard

Import dashboard JSON or create custom dashboard with these queries:

```promql
# Probe success rate
rate(probe_success{job=~"blackbox-.*"}[5m])

# HTTP response time
probe_http_duration_seconds{job="blackbox-http"}

# SSL certificate days until expiry
(probe_ssl_earliest_cert_expiry - time()) / 86400

# DNS lookup time
probe_dns_lookup_time_seconds

# TCP connection time
probe_tcp_duration_seconds

# Uptime percentage (last 24h)
avg_over_time(probe_success{job="blackbox-http"}[24h]) * 100

# Status code distribution
sum by (status_code) (probe_http_status_code)
```

## 7. Security Considerations

### Network Security

```bash
# Firewall rules
sudo ufw allow from prometheus_server_ip to any port 9115

# iptables
sudo iptables -A INPUT -p tcp --dport 9115 -s prometheus_server_ip -j ACCEPT
```

### Authentication

Enable basic auth in blackbox exporter:
```bash
# Generate password hash
htpasswd -nBC 10 "" | tr -d ':\n'

# Add to blackbox_exporter command
--web.config=/etc/blackbox_exporter/web.yml
```

Create `/etc/blackbox_exporter/web.yml`:
```yaml
basic_auth_users:
  prometheus: $2b$10$...  # bcrypt hash
```

### TLS Configuration

```yaml
tls_server_config:
  cert_file: /etc/blackbox_exporter/server.crt
  key_file: /etc/blackbox_exporter/server.key
```

## 6. Troubleshooting

### Testing Probes

```bash
# Test HTTP probe
curl "http://localhost:9115/probe?target=https://example.com&module=http_2xx"

# Test with debug
curl "http://localhost:9115/probe?target=https://example.com&module=http_2xx&debug=true"

# Check metrics
curl http://localhost:9115/metrics
```

### Common Issues

1. **ICMP permission denied**:
```bash
# Set capability
sudo setcap cap_net_raw+ep /usr/local/bin/blackbox_exporter

# Or run as root (not recommended)
```

2. **Connection refused**:
```bash
# Check service status
sudo systemctl status blackbox_exporter

# Check logs
sudo journalctl -u blackbox_exporter -f

# Verify listening port
sudo netstat -tlnp | grep 9115
```

3. **SSL verification failures**:
```yaml
# Temporarily disable verification (testing only)
tls_config:
  insecure_skip_verify: true
```

## 8. Performance Tuning

### Concurrent Probes

```bash
# Increase concurrent probes
--web.max-requests=100
```

### Timeout Optimization

```yaml
# Adjust timeouts based on network conditions
modules:
  http_fast:
    prober: http
    timeout: 2s
  http_slow:
    prober: http
    timeout: 30s
```

### Resource Limits

```ini
# In systemd service file
[Service]
LimitNOFILE=65535
MemoryLimit=256M
CPUQuota=50%
```

## Monitoring Best Practices

1. **Probe frequency**: Balance between detection speed and load
2. **Timeout values**: Set slightly below scrape interval
3. **Module reuse**: Create specific modules for different use cases
4. **Geographic distribution**: Deploy multiple blackbox exporters
5. **Internal vs external**: Separate probes for internal/external services

## Additional Resources

- [Official Documentation](https://github.com/prometheus/blackbox_exporter)
- [Configuration Examples](https://github.com/prometheus/blackbox_exporter/blob/master/example.yml)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards?search=blackbox)
- [Community Forum](https://groups.google.com/forum/#!forum/prometheus-users)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.