#!/usr/bin/env python3
"""
Syslog TCP/UDP receiver that pushes messages into Redis.

Listens on a configurable port for syslog messages over TCP and UDP,
and pushes each line into a Redis list for the AI service to consume.

Designed to sit between syslog-ng/rsyslog remote forwarding and the
AI log filter pipeline.
"""

import os
import sys
import socket
import signal
import logging
import threading
import time

import redis as redispy

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "5514"))
REDIS_HOST = os.getenv("REDIS_HOST", "redis://redis:6379")
REDIS_KEY = os.getenv("REDIS_KEY", "filebeat:logs")
# Max TCP connections to handle concurrently
MAX_TCP_CONNECTIONS = int(os.getenv("MAX_TCP_CONNECTIONS", "64"))
# TCP receive buffer size
TCP_BUFFER_SIZE = int(os.getenv("TCP_BUFFER_SIZE", "65536"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("syslog-receiver")

# Graceful shutdown
shutdown_event = threading.Event()


def _handle_signal(signum, frame):
    log.info("Received signal %s, shutting down ...", signum)
    shutdown_event.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ---------------------------------------------------------------------------
# Redis connection with reconnect
# ---------------------------------------------------------------------------
class RedisWriter:
    """Thread-safe Redis writer with automatic reconnection."""

    def __init__(self, redis_url: str, redis_key: str):
        self.redis_url = redis_url
        self.redis_key = redis_key
        self._client = None
        self._lock = threading.Lock()
        self._stats_total = 0
        self._stats_errors = 0

    def _connect(self):
        self._client = redispy.Redis.from_url(
            self.redis_url, decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        self._client.ping()

    def push(self, message: str):
        """Push a single message to the Redis list. Reconnects on failure."""
        with self._lock:
            try:
                if self._client is None:
                    self._connect()
                self._client.rpush(self.redis_key, message)
                self._stats_total += 1
            except (redispy.ConnectionError, redispy.TimeoutError, OSError) as e:
                self._stats_errors += 1
                self._client = None
                log.warning("Redis push failed (will reconnect): %s", e)
            except Exception as e:
                self._stats_errors += 1
                log.warning("Redis push unexpected error: %s", e)

    def push_batch(self, messages: list):
        """Push multiple messages to Redis in a pipeline (faster)."""
        if not messages:
            return
        with self._lock:
            try:
                if self._client is None:
                    self._connect()
                pipe = self._client.pipeline(transaction=False)
                for msg in messages:
                    pipe.rpush(self.redis_key, msg)
                pipe.execute()
                self._stats_total += len(messages)
            except (redispy.ConnectionError, redispy.TimeoutError, OSError) as e:
                self._stats_errors += len(messages)
                self._client = None
                log.warning("Redis batch push failed (will reconnect): %s", e)
            except Exception as e:
                self._stats_errors += len(messages)
                log.warning("Redis batch push unexpected error: %s", e)

    @property
    def stats(self):
        return self._stats_total, self._stats_errors


# ---------------------------------------------------------------------------
# TCP handler - one thread per connection
# ---------------------------------------------------------------------------
def handle_tcp_connection(conn: socket.socket, addr, writer: RedisWriter):
    """Handle a single TCP syslog connection."""
    log.info("[tcp] New connection from %s:%d", addr[0], addr[1])
    conn.settimeout(30.0)
    buffer = ""
    count = 0

    try:
        while not shutdown_event.is_set():
            try:
                data = conn.recv(TCP_BUFFER_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break

            if not data:
                break

            buffer += data.decode("utf-8", errors="replace")

            # Split on newlines - syslog messages are line-delimited
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if line:
                    # Strip syslog framing if present (RFC 5425 octet counting)
                    # e.g., "123 <14>Mar 24 ..." -> strip the leading length
                    if line[0].isdigit() and " " in line:
                        first_space = line.index(" ")
                        potential_len = line[:first_space]
                        if potential_len.isdigit():
                            line = line[first_space + 1:]

                    writer.push(line)
                    count += 1

        # Flush remaining buffer
        if buffer.strip():
            writer.push(buffer.strip())
            count += 1

    except Exception as e:
        log.warning("[tcp] Error handling connection from %s: %s", addr, e)
    finally:
        conn.close()
        log.info("[tcp] Connection from %s:%d closed (%d messages)", addr[0], addr[1], count)


# ---------------------------------------------------------------------------
# TCP server
# ---------------------------------------------------------------------------
def run_tcp_server(writer: RedisWriter):
    """Run the TCP syslog server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(MAX_TCP_CONNECTIONS)

    log.info("[tcp] Listening on %s:%d", LISTEN_HOST, LISTEN_PORT)

    threads = []
    while not shutdown_event.is_set():
        try:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_tcp_connection,
                args=(conn, addr, writer),
                daemon=True,
            )
            t.start()
            threads.append(t)

            # Clean up finished threads
            threads = [t for t in threads if t.is_alive()]
        except socket.timeout:
            continue
        except OSError:
            if not shutdown_event.is_set():
                log.warning("[tcp] Accept error")
            break

    server.close()
    log.info("[tcp] Server stopped")


# ---------------------------------------------------------------------------
# UDP server
# ---------------------------------------------------------------------------
def run_udp_server(writer: RedisWriter):
    """Run the UDP syslog server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)
    server.bind((LISTEN_HOST, LISTEN_PORT))

    log.info("[udp] Listening on %s:%d", LISTEN_HOST, LISTEN_PORT)

    batch = []
    batch_time = time.time()

    while not shutdown_event.is_set():
        try:
            data, addr = server.recvfrom(65535)
            if data:
                message = data.decode("utf-8", errors="replace").strip()
                if message:
                    batch.append(message)

                    # Flush batch every 100 messages or every 0.5 seconds
                    if len(batch) >= 100 or (time.time() - batch_time) > 0.5:
                        writer.push_batch(batch)
                        batch = []
                        batch_time = time.time()

        except socket.timeout:
            # Flush whatever we have on timeout
            if batch:
                writer.push_batch(batch)
                batch = []
                batch_time = time.time()
            continue
        except OSError:
            if not shutdown_event.is_set():
                log.warning("[udp] Receive error")
            break

    # Final flush
    if batch:
        writer.push_batch(batch)

    server.close()
    log.info("[udp] Server stopped")


# ---------------------------------------------------------------------------
# Stats reporter
# ---------------------------------------------------------------------------
def run_stats_reporter(writer: RedisWriter):
    """Periodically log stats."""
    last_total = 0
    while not shutdown_event.is_set():
        shutdown_event.wait(30)
        total, errors = writer.stats
        delta = total - last_total
        last_total = total
        log.info(
            "STATS | total_received=%d (+%d) errors=%d",
            total, delta, errors,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    log.info("=" * 60)
    log.info("Syslog Receiver - Starting up")
    log.info("=" * 60)
    log.info("Config: LISTEN=%s:%d (TCP+UDP)", LISTEN_HOST, LISTEN_PORT)
    log.info("Config: REDIS_HOST=%s", REDIS_HOST)
    log.info("Config: REDIS_KEY=%s", REDIS_KEY)

    # Wait for Redis
    writer = RedisWriter(REDIS_HOST, REDIS_KEY)
    for attempt in range(30):
        try:
            writer._connect()
            log.info("Redis connected.")
            break
        except Exception as e:
            log.info("Waiting for Redis (attempt %d/30): %s", attempt + 1, e)
            time.sleep(2)
    else:
        log.error("Could not connect to Redis after 30 attempts.")
        sys.exit(1)

    # Start servers in threads
    tcp_thread = threading.Thread(target=run_tcp_server, args=(writer,), daemon=True)
    udp_thread = threading.Thread(target=run_udp_server, args=(writer,), daemon=True)
    stats_thread = threading.Thread(target=run_stats_reporter, args=(writer,), daemon=True)

    tcp_thread.start()
    udp_thread.start()
    stats_thread.start()

    log.info("Syslog receiver ready. Accepting connections.")

    # Wait for shutdown
    try:
        while not shutdown_event.is_set():
            shutdown_event.wait(1)
    except KeyboardInterrupt:
        shutdown_event.set()

    log.info("Shutting down ...")
    total, errors = writer.stats
    log.info("Final stats: total=%d errors=%d", total, errors)


if __name__ == "__main__":
    main()
