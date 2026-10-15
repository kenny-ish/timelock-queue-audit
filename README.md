# timelock-queue-audit

`timelock-queue-audit` finds Compound-style Timelock queue entries in a block range, checks each transaction's `queuedTransactions(bytes32)` value with `eth_call`, and prints the target, calldata, ETA, delay, and current status. It uses only the RPC endpoint supplied by the user.

## Example

Against Ethereum mainnet at block 21758256:

```text
$ python timelock_queue_audit.py --rpc https://eth.drpc.org --timelock 0x6d903f6003cca6255d85cca4d3b5e5146dc33925 --from-block 21758256 --to-block 21758256 --chunk-size 100 --include-completed
Timelock 0x6d903f6003cca6255d85cca4d3b5e5146dc33925 blocks 21758256-21758256
Chain time: 2025-02-02 10:33:35 UTC delay=172800s
inactive  0x172fc585bd19c0674537c9907578102d135871a05f193b6c6475b222263deca3 ready_at=2025-02-04 10:33:35 UTC target=0x309a862bbc1a00e45506cb8a802d1ff10004c8c0 value=0 signature='setNextProposalId()' data=0x
inactive  0x72149f9bb91163f1bf450ce9243bef9c4ab73f3988e50960f352eb9fdfd3ceb0 ready_at=2025-02-04 10:33:35 UTC target=0x309a862bbc1a00e45506cb8a802d1ff10004c8c0 value=0 signature='__acceptAdmin()' data=0x
inactive  0x9e592ec742ce93ef153de7f1d29b596fc184fe2c836c91d233feed819b223c6b ready_at=2025-02-04 10:33:35 UTC target=0x6d903f6003cca6255d85cca4d3b5e5146dc33925 value=0 signature='setPendingAdmin(address)' data=0x000000000000000000000000309a862bbc1a00e45506cb8a802d1ff10004c8c0
```

## Usage

```text
python timelock_queue_audit.py --rpc RPC_URL --timelock ADDRESS --from-block N [--to-block N|latest] [--chunk-size N] [--include-completed] [--json]
```

`--from-block` is required because logs are not an index. Use `--include-completed` to retain entries that are no longer live. The program retries a rejected log window with smaller windows.

## How it works

It computes the Compound Timelock event topics with a small Keccak-256 implementation, reads `QueueTransaction`, `ExecuteTransaction`, and `CancelTransaction` logs, and decodes the ABI fields. It then calls `queuedTransactions(bytes32)` and `delay()`, reads the end block timestamp, and compares it with each ETA. No transaction is sent.

## Tests

```text
python -m unittest -v
```
