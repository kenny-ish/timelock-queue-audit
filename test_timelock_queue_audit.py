import unittest
from unittest.mock import patch

import timelock_queue_audit as tool


def abi_word(value):
    return value.to_bytes(32, "big")


# Fields and block metadata are copied from the Ethereum mainnet event at block 21758256.
# The ABI words below are kept as values so the fixed fixture is easy to audit.
REAL_SIGNATURE = b"setNextProposalId()"
REAL_QUEUE_DATA = b"".join(
    [
        abi_word(0),
        abi_word(128),
        abi_word(192),
        abi_word(1738665215),
        abi_word(len(REAL_SIGNATURE)),
        REAL_SIGNATURE.ljust(32, b"\0"),
        abi_word(0),
    ]
)
REAL_QUEUE_LOG = {
    "address": "0x6d903f6003cca6255d85cca4d3b5e5146dc33925",
    "topics": [
        "0x76e2796dc3a81d57b0e8504b647febcbeeb5f4af818e164f11eef8131a6a763f",
        "0x172fc585bd19c0674537c9907578102d135871a05f193b6c6475b222263deca3",
        "0x000000000000000000000000309a862bbc1a00e45506cb8a802d1ff10004c8c0",
    ],
    "data": "0x" + REAL_QUEUE_DATA.hex(),
    "blockNumber": "0x14c0130",
    "transactionHash": "0x2c8b270ea62d257af9d49863e530d2da50ecb993347e6b8fd3167e7a2ed2de88",
    "logIndex": "0x113",
}


class FakeRpc:
    def __init__(self, queued=False):
        self.queued = queued
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "eth_getLogs":
            topic = params[0]["topics"][0]
            if topic == tool.QUEUE_TOPIC:
                return [REAL_QUEUE_LOG]
            return []
        if method == "eth_getBlockByNumber":
            return {"timestamp": "0x679f49ff"}
        if method == "eth_call":
            data = params[0]["data"]
            if data.startswith("0x" + tool.DELAY_SELECTOR.hex()):
                return "0x" + (172800).to_bytes(32, "big").hex()
            if data.startswith("0x" + tool.QUEUED_SELECTOR.hex()):
                return "0x" + (1 if self.queued else 0).to_bytes(32, "big").hex()
        raise AssertionError((method, params))


class TimelockQueueAuditTests(unittest.TestCase):
    def test_keccak_empty_is_ethereum_keccak(self):
        self.assertEqual(
            tool.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_decodes_a_real_compound_queue_event(self):
        row = tool._decode_queue(REAL_QUEUE_LOG)
        self.assertEqual(row["tx_hash"], "0x172fc585bd19c0674537c9907578102d135871a05f193b6c6475b222263deca3")
        self.assertEqual(row["target"], "0x309a862bbc1a00e45506cb8a802d1ff10004c8c0")
        self.assertEqual(row["signature"], "setNextProposalId()")
        self.assertEqual(row["data"], "0x")
        self.assertEqual(row["eta"], 1738665215)
        self.assertEqual(row["block_number"], 21758256)

    def test_scan_combines_logs_eth_call_and_block_time(self):
        rpc = FakeRpc(queued=True)
        result = tool.scan_timelock(
            rpc,
            "0x6d903f6003cca6255d85cca4d3b5e5146dc33925",
            21758256,
            21758256,
            chunk_size=100,
        )
        self.assertEqual(result["delay_seconds"], 172800)
        self.assertEqual(result["chain_timestamp"], 1738492415)
        self.assertEqual(result["operations"][0]["status"], "waiting")
        self.assertEqual(result["operations"][0]["ready_at"], "2025-02-04 10:33:35 UTC")
        self.assertTrue(any(call[0] == "eth_call" for call in rpc.calls))

    def test_requeued_transaction_is_live_after_cancellation(self):
        block_number = int(REAL_QUEUE_LOG["blockNumber"], 16)
        eta = tool._decode_queue(REAL_QUEUE_LOG)["eta"]
        cancelled_log = dict(
            REAL_QUEUE_LOG,
            topics=[tool.CANCEL_TOPIC] + REAL_QUEUE_LOG["topics"][1:],
            blockNumber=hex(block_number + 1),
            transactionHash="0x" + "11" * 32,
            logIndex="0x0",
        )
        requeued_log = dict(
            REAL_QUEUE_LOG,
            blockNumber=hex(block_number + 2),
            transactionHash="0x" + "22" * 32,
            logIndex="0x0",
        )
        for timestamp, status in ((eta - 1, "waiting"), (eta, "ready"), (eta + 1, "ready")):
            for include_completed in (False, True):
                with self.subTest(timestamp=timestamp, include_completed=include_completed):
                    rpc = FakeRpc(queued=True)
                    fake_call = rpc.call

                    def call(method, params):
                        if method == "eth_getLogs":
                            return {
                                tool.QUEUE_TOPIC: [REAL_QUEUE_LOG, requeued_log],
                                tool.CANCEL_TOPIC: [cancelled_log],
                                tool.EXECUTE_TOPIC: [],
                            }[params[0]["topics"][0]]
                        if method == "eth_getBlockByNumber":
                            return {"timestamp": hex(timestamp)}
                        return fake_call(method, params)

                    with patch.object(rpc, "call", side_effect=call):
                        result = tool.scan_timelock(
                            rpc,
                            REAL_QUEUE_LOG["address"],
                            block_number,
                            block_number + 3,
                            include_completed=include_completed,
                        )
                    self.assertEqual(len(result["operations"]), 1)
                    row = result["operations"][0]
                    self.assertEqual(row["status"], status)
                    self.assertTrue(row["queued"])
                    self.assertEqual(row["tx_hash"], REAL_QUEUE_LOG["topics"][1])
                    self.assertEqual(row["eta"], eta)
                    self.assertEqual(row["block_number"], block_number + 2)

    def test_inactive_event_is_hidden_by_default(self):
        rpc = FakeRpc(queued=False)
        result = tool.scan_timelock(
            rpc,
            "0x6d903f6003cca6255d85cca4d3b5e5146dc33925",
            21758256,
            21758256,
            include_completed=False,
            chunk_size=100,
        )
        self.assertEqual(result["operations"], [])


if __name__ == "__main__":
    unittest.main()
