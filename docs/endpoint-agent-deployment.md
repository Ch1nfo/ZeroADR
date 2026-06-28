# Endpoint Agent Deployment

ZeroADR v0.6 turns the endpoint agent into a deployable local production
baseline. The agent still writes local JSONL, SQLite, and a status file; the
Console reads agent health through the read-only HTTP API.

## Recommended Local Layout

```text
.zeroadr/
  endpoint-agent.jsonl
  endpoint-agent-status.json
  endpoint-agent.pid
  zeroadr.sqlite
  traces/
    endpoint-agent.jsonl
```

## Cross-Platform Demo

Terminal 1: run the endpoint agent

```bash
pip install -e .

zeroadr endpoint agent \
  --collector mock \
  --output .zeroadr/endpoint-agent.jsonl \
  --status-file .zeroadr/endpoint-agent-status.json \
  --pid-file .zeroadr/endpoint-agent.pid \
  --trace .zeroadr/traces/endpoint-agent.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  --strict-ingest \
  --heartbeat-interval 5
```

Terminal 2: run the API server and Console

```bash
zeroadr api serve \
  --db .zeroadr/zeroadr.sqlite \
  --agent-status-file .zeroadr/endpoint-agent-status.json \
  --host 127.0.0.1 \
  --port 8765
```

Open:

```text
http://127.0.0.1:8765/console
```

The Console shows endpoint agent health from
`GET /api/v0/endpoint-agent/health`.

## Linux systemd

Template:

- [`deploy/systemd/zeroadr-endpoint-agent.service`](../deploy/systemd/zeroadr-endpoint-agent.service)

Install example:

```bash
sudo cp deploy/systemd/zeroadr-endpoint-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zeroadr-endpoint-agent
sudo systemctl start zeroadr-endpoint-agent
sudo systemctl status zeroadr-endpoint-agent
```

Health check:

```bash
zeroadr endpoint status --status-file .zeroadr/endpoint-agent-status.json --stale-after 30
```

## Linux BCC Production (v0.8)

For privileged Linux hosts with BCC installed:

```bash
sudo apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
python3 -m pip install -e .
export ZEROADR_ENABLE_BCC=1

zeroadr endpoint agent \
  --collector linux \
  --output .zeroadr/endpoint-agent.jsonl \
  --status-file .zeroadr/endpoint-agent-status.json \
  --pid-file .zeroadr/endpoint-agent.pid \
  --trace .zeroadr/traces/endpoint-agent.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  --strict-ingest \
  --heartbeat-interval 5
```

Do not install the unrelated PyPI project named `bcc`. The endpoint agent must
run with an interpreter that can import the iovisor/BCC bindings supplied by
`python3-bpfcc` or a source installation.

systemd template:

- [`deploy/systemd/zeroadr-endpoint-agent-linux.service`](../deploy/systemd/zeroadr-endpoint-agent-linux.service)

Install example:

```bash
sudo cp deploy/systemd/zeroadr-endpoint-agent-linux.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zeroadr-endpoint-agent-linux
sudo systemctl start zeroadr-endpoint-agent-linux
sudo systemctl status zeroadr-endpoint-agent-linux
```

The status file includes a `bcc` probe section when `--collector linux` is
running. Console renders probe attach state, event counts, and dropped events.

See [`docs/linux-ebpf-collector.md`](linux-ebpf-collector.md) for permissions,
path filters, and troubleshooting.

## macOS launchd

Template:

- [`deploy/launchd/com.zeroadr.endpoint-agent.plist`](../deploy/launchd/com.zeroadr.endpoint-agent.plist)

Install example:

```bash
sudo cp deploy/launchd/com.zeroadr.endpoint-agent.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.zeroadr.endpoint-agent.plist
sudo launchctl kickstart -k system/com.zeroadr.endpoint-agent
```

## Windows

ZeroADR v0.6 does not ship a Windows Service installer yet. Use two terminals:

1. Install the project: `python -m pip install -e .`
2. Start the endpoint agent with the same flags as the cross-platform demo.
3. Start `zeroadr api serve --agent-status-file .zeroadr/endpoint-agent-status.json`.
4. Open `http://127.0.0.1:8765/console`.

For unattended use, Task Scheduler can run the same commands at logon.

## Current Limitations

- Localhost-oriented deployment only.
- No Windows Service or macOS/Linux API server supervisor templates yet.
- Linux BCC production uses privileged hosts; mock collector remains the default cross-platform template.
- No remote storage, auth, or WebSocket streaming.
