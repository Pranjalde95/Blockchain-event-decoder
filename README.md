# Blockchain Event Log Decoder

A universal, multi-protocol event log decoder for DeFi (Aave, Uniswap, ERC-20, system events). It identifies protocol type from contract addresses, recognizes event signatures, and decodes indexed/unindexed parameters into structured JSON.

> **Runs locally or in Colab.** Input: `sample.json` (Polygon/EVM-style logs). Output: `decoded_events_output.json`.

## Features
- Protocol identification (lending/DEX/system/token/unknown) via address maps
- Multi-protocol event signature map (ERC-20, Uniswap V2/V3, Aave V3, ERC-1155, etc.)
- Universal decoder for topics/data (indexed + unindexed params)
- Graceful fallbacks for unknown signatures
- Summary analytics: event type distribution, protocols identified

## Project Structure
```
.
├── README.md
├── requirements.txt
├── sample.json
├── src
│   ├── decoder_core.py      # All helper fns + metadata + decoder
│   └── main.py              # CLI entrypoint: reads JSON, writes decoded output
├── tests
│   └── test_decoder.py      # Pytest unit tests for core logic
├── docs
│   └── technical_report.md  # Detailed methodology (optional for submission)
└── artifacts
    └── decoded_events_output.sample.json  # Example output for reference
```
> If you only need the code + README, you can remove `docs/` and `artifacts/` before pushing.

## Quick Start
```bash
pip install -r requirements.txt
python -m src.main --input sample.json --out decoded_events_output.json
```

**CLI options**
```
--input / -i    Path to input JSON file of logs (default: sample.json)
--out   / -o    Path to write decoded output JSON (default: decoded_events_output.json)
--limit / -n    Optional: only process first N logs (debugging)
```

## Run Tests
```bash
pip install -r requirements.txt
pytest -q
```

## How It Works (Phase mapping)
- **Phase 1**: Environment & imports (see `requirements.txt`)
- **Phase 2**: Helpers & metadata (`TOKENS`, `PROTOCOLS`)
- **Phase 3**: Event signature map (keccak(topic0) → name + ABI inputs)
- **Phase 4**: Load logs (expects EVM log shape: `address`, `topics`, `data`, etc.)
- **Phase 5**: Contract → protocol classification
- **Phase 6**: Universal event decoder (indexed/unindexed params)
- **Phase 7**: Aggregate + summarize
- **Phase 8**: CLI output (write JSON file + console summary)

## Input Format (`sample.json`)
- Either a list of logs, **or** an object with `{ "wallet": "...", "logs": [...] }`
- Each log should include typical EVM fields:
  - `address`, `topics` (topic0 = keccak of signature), `data` (ABI-encoded)
  - `blockNumber`, `transactionHash`, `logIndex` (hex or int accepted)

A minimal example is provided in `sample.json` (ERC-20 `Transfer`).

## Notes & Limits
- Unknown event signatures are labeled `eventName="Unknown"` with a `note`
- Address→protocol coverage is partial (extend `TOKENS`/`PROTOCOLS` as needed)
- Multi-chain works if logs follow the same EVM log schema
