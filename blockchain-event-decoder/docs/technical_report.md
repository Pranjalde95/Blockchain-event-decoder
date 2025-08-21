# Technical Report: Multi-Protocol Blockchain Event Log Decoder

## 1. Introduction
This project addresses the challenge of decoding raw blockchain event logs from multiple decentralized finance (DeFi) protocols, focusing on lending, decentralized exchange (DEX), staking, and system-level events. The goal is to build a universal service that can automatically identify, classify, and decode events present in large-scale datasets of EVM logs.

## 2. Protocol Identification
**Methodology:** map contract addresses → protocols/types via curated dictionaries, explorer lookups, and heuristics. **Outcome:** coverage for Aave V3 (lending), Uniswap V3 (DEX), Permit2 (system), and key tokens (USDC/USDT/WBTC). Unknowns default to `Unknown/unknown` for graceful handling.

## 3. Event Signature Recognition
Event `topic0` is `keccak256("EventName(types...)")`. We maintain a multi-protocol signature table covering ERC-20/1155, Uniswap V2/V3, and Aave V3 core events. Collisions are disambiguated by protocol context (contract address).

## 4. Universal Event Decoding
We decode indexed params (from topics[1..]) and unindexed params (from `data`) using ABI types bound to the signature. Addresses are normalized to EIP‑55 checksum. All decoded fields are returned as a flat `decodedData` map.

## 5. Output & Analytics
The decoder aggregates results by `protocolType` and emits:
- `summary` (totals, protocol names per type, eventTypeDistribution)
- `eventsByProtocol` (lists of event entries with tx meta + decoded fields)

## 6. Performance & Extensibility
Stateless, linear pass over logs; easily parallelizable. Add support by extending: `TOKENS`, `PROTOCOLS`, signature table, or by wiring ABIs where needed.

## 7. Limitations & Future Work
- Unknown/custom signatures remain `Unknown` without ABIs
- Address labeling is partial; may need automated sources
- Future: on-the-fly ABI fetch, more chains/protocols, stream decoding

## 8. Conclusion
A clean, extensible foundation for multi-protocol EVM log decoding with practical summaries for analytics.
