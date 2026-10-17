#!/usr/bin/env python3
"""List live Compound-style Timelock queue entries using JSON-RPC only."""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

MASK64 = (1 << 64) - 1


def _rot(value: int, shift: int) -> int:
    value &= MASK64
    return value if shift == 0 else ((value << shift) | (value >> (64 - shift))) & MASK64


def _lfsr_bit(t: int) -> int:
    value = 0x01
    for _ in range(t % 255):
        high = value & 0x80
        value = ((value << 1) & 0xFF) ^ (0x71 if high else 0)
    return value & 1


def _round_constants() -> List[int]:
    # Keccak's round constants are generated from the specified 8-bit LFSR.
    return [
        sum(_lfsr_bit(j + 7 * round_number) << ((1 << j) - 1) for j in range(7))
        for round_number in range(24)
    ]


def _rotation_offsets() -> List[List[int]]:
    offsets = [[0 for _ in range(5)] for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        offsets[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


ROUND_CONSTANTS = _round_constants()
ROTATION_OFFSETS = _rotation_offsets()


def _keccak_f(state: List[int]) -> None:
    for constant in ROUND_CONSTANTS:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot(c[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for y in range(5):
            for x in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rot(state[x + 5 * y], ROTATION_OFFSETS[x][y])
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= constant


def keccak256(data: bytes) -> bytes:
    """Keccak-256, with Ethereum's 0x01 suffix rather than SHA3's 0x06."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        _keccak_f(state)
    output = bytearray()
    while len(output) < 32:
        for i in range(rate // 8):
            output.extend(state[i].to_bytes(8, "little"))
        if len(output) < 32:
            _keccak_f(state)
    return bytes(output[:32])


def function_selector(signature: str) -> bytes:
    return keccak256(signature.encode("ascii"))[:4]


def event_topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode("ascii")).hex()


QUEUE_TOPIC = event_topic("QueueTransaction(bytes32,address,uint256,string,bytes,uint256)")
EXECUTE_TOPIC = event_topic("ExecuteTransaction(bytes32,address,uint256,string,bytes,uint256)")
CANCEL_TOPIC = event_topic("CancelTransaction(bytes32,address,uint256,string,bytes,uint256)")
QUEUED_SELECTOR = function_selector("queuedTransactions(bytes32)")
DELAY_SELECTOR = function_selector("delay()")


def _quantity(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"invalid JSON-RPC quantity: {value!r}")
    return int(value, 16)


def _hex_bytes(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("expected a 0x-prefixed hex string")
    return bytes.fromhex(value[2:])


def _word(data: bytes, index: int) -> int:
    start = index * 32
    if start + 32 > len(data):
        raise ValueError("short ABI event data")
    return int.from_bytes(data[start : start + 32], "big")


def _dynamic(data: bytes, word_index: int) -> bytes:
    offset = _word(data, word_index)
    length = _word(data, offset // 32)
    start = offset + 32
    if start + length > len(data):
        raise ValueError("short ABI dynamic value")
    return data[start : start + length]


def _address_word(value: int) -> str:
    return "0x" + (value & ((1 << 160) - 1)).to_bytes(20, "big").hex()


def _bytes32(topic: str) -> str:
    raw = _hex_bytes(topic)
    if len(raw) != 32:
        raise ValueError("expected a bytes32 topic")
    return "0x" + raw.hex()


def _decode_queue(log: Dict[str, Any]) -> Dict[str, Any]:
    topics = log.get("topics", [])
    if len(topics) < 3:
        raise ValueError("QueueTransaction has too few topics")
    data = _hex_bytes(log.get("data", "0x"))
    return {
        "tx_hash": _bytes32(topics[1]),
        "target": _address_word(_quantity(topics[2])),
        "value_wei": _word(data, 0),
        "signature": _dynamic(data, 1).decode("utf-8", errors="replace"),
        "data": "0x" + _dynamic(data, 2).hex(),
        "eta": _word(data, 3),
        "block_number": _quantity(log["blockNumber"]),
        "transaction_hash": log.get("transactionHash"),
        "log_index": _quantity(log.get("logIndex", "0x0")),
    }


def _event_id(log: Dict[str, Any]) -> str:
    topics = log.get("topics", [])
    if len(topics) < 2:
        raise ValueError("Timelock event has too few topics")
    return _bytes32(topics[1])


class JsonRpcError(RuntimeError):
    pass


class JsonRpcClient:
    def __init__(self, url: str, timeout: float = 30.0, opener: Any = urllib.request.urlopen) -> None:
        self.url = url
        self.timeout = timeout
        self.opener = opener
        self._next_id = 1

    def call(self, method: str, params: List[Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "timelock-queue-audit/1.0"},
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise JsonRpcError(f"RPC request failed: {exc}") from exc
        if payload.get("error") is not None:
            raise JsonRpcError(str(payload["error"]))
        return payload.get("result")


def _ranges(start: int, end: int, size: int) -> Iterable[Tuple[int, int]]:
    cursor = start
    while cursor <= end:
        yield cursor, min(end, cursor + size - 1)
        cursor += size


def _logs_once(client: JsonRpcClient, address: str, start: int, end: int, topic: str) -> List[Dict[str, Any]]:
    return client.call("eth_getLogs", [{"address": address, "fromBlock": hex(start), "toBlock": hex(end), "topics": [topic]}])


def _logs(client: JsonRpcClient, address: str, start: int, end: int, topic: str, chunk_size: int) -> List[Dict[str, Any]]:
    """Query bounded ranges and halve a range when a provider rejects it."""
    result: List[Dict[str, Any]] = []
    for left, right in _ranges(start, end, chunk_size):
        pending = [(left, right)]
        while pending:
            a, b = pending.pop()
            try:
                result.extend(_logs_once(client, address, a, b, topic))
            except JsonRpcError:
                if a == b:
                    raise
                middle = (a + b) // 2
                pending.extend([(middle + 1, b), (a, middle)])
    return result


def _block_timestamp(client: JsonRpcClient, block_number: int) -> int:
    block = client.call("eth_getBlockByNumber", [hex(block_number), False])
    if not block:
        raise JsonRpcError(f"block {block_number} was not returned")
    return _quantity(block["timestamp"])


def _bool_call(client: JsonRpcClient, timelock: str, tx_hash: str) -> bool:
    data = "0x" + (QUEUED_SELECTOR + _hex_bytes(tx_hash)).hex()
    raw = _hex_bytes(client.call("eth_call", [{"to": timelock, "data": data}, "latest"]))
    return bool(_word(raw, 0))


def _uint_call(client: JsonRpcClient, timelock: str, selector: bytes) -> int:
    raw = _hex_bytes(client.call("eth_call", [{"to": timelock, "data": "0x" + selector.hex()}, "latest"]))
    return _word(raw, 0)


def _utc(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def scan_timelock(
    client: JsonRpcClient,
    timelock: str,
    from_block: int,
    to_block: Optional[int] = None,
    include_completed: bool = False,
    chunk_size: int = 5000,
) -> Dict[str, Any]:
    """Return current Compound Timelock queue entries and their on-chain ETA."""
    if to_block is None:
        to_block = _quantity(client.call("eth_blockNumber", []))
    if from_block < 0 or to_block < from_block:
        raise ValueError("invalid block range")
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    queued = [_decode_queue(log) for log in _logs(client, timelock, from_block, to_block, QUEUE_TOPIC, chunk_size)]
    executed = {_event_id(log) for log in _logs(client, timelock, from_block, to_block, EXECUTE_TOPIC, chunk_size)}
    cancelled = {_event_id(log) for log in _logs(client, timelock, from_block, to_block, CANCEL_TOPIC, chunk_size)}
    latest_block = to_block
    chain_timestamp = _block_timestamp(client, latest_block)
    delay = _uint_call(client, timelock, DELAY_SELECTOR)
    operations: Dict[str, Dict[str, Any]] = {}
    for item in queued:
        operations[item["tx_hash"]] = item
    rows: List[Dict[str, Any]] = []
    for tx_hash, item in operations.items():
        is_queued = _bool_call(client, timelock, tx_hash)
        if is_queued:
            status = "ready" if item["eta"] <= chain_timestamp else "waiting"
        elif tx_hash in executed:
            status = "executed"
        elif tx_hash in cancelled:
            status = "cancelled"
        else:
            status = "inactive"
        if not include_completed and status not in {"waiting", "ready"}:
            continue
        row = dict(item)
        row.update({"status": status, "ready_at": _utc(item["eta"]), "queued": is_queued})
        rows.append(row)
    rows.sort(key=lambda row: (row["eta"], row["tx_hash"]))
    return {
        "timelock": timelock,
        "from_block": from_block,
        "to_block": to_block,
        "chain_timestamp": chain_timestamp,
        "chain_time": _utc(chain_timestamp),
        "delay_seconds": delay,
        "operations": rows,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit Compound Timelock queue entries from RPC logs and eth_call.")
    parser.add_argument("--rpc", required=True, help="JSON-RPC URL")
    parser.add_argument("--timelock", required=True, help="Compound Timelock address")
    parser.add_argument("--from-block", required=True, type=int, help="inclusive log start block")
    parser.add_argument("--to-block", default="latest", help="inclusive log end block, or latest")
    parser.add_argument("--chunk-size", default=5000, type=int, help="initial eth_getLogs block window")
    parser.add_argument("--include-completed", action="store_true", help="also print executed, cancelled, and inactive records")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit JSON")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    timelock = args.timelock.lower()
    if len(timelock) != 42 or not timelock.startswith("0x"):
        raise SystemExit("--timelock must be a 20-byte 0x address")
    client = JsonRpcClient(args.rpc)
    to_block = None if args.to_block == "latest" else int(args.to_block, 0)
    try:
        result = scan_timelock(client, timelock, args.from_block, to_block, args.include_completed, args.chunk_size)
    except (ValueError, JsonRpcError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    print(f"Timelock {result['timelock']} blocks {result['from_block']}-{result['to_block']}")
    print(f"Chain time: {result['chain_time']} delay={result['delay_seconds']}s")
    if not result["operations"]:
        print("No matching live operations.")
        return 0
    for row in result["operations"]:
        print(f"{row['status']:9} {row['tx_hash']} ready_at={row['ready_at']} target={row['target']} value={row['value_wei']} signature={row['signature']!r} data={row['data']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
