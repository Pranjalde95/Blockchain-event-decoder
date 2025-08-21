from typing import Dict, Tuple, Optional
from web3 import Web3
from eth_abi import decode_abi
from collections import defaultdict, Counter

# === Phase 2: Helper Functions and Metadata ===
def keccak_sig(text: str) -> str:
    return Web3.keccak(text=text).hex()

def hex_to_int(x: str) -> int:
    if x is None or x == "0x" or x == "":
        return 0
    return int(x, 16)

def hex_addr(x: str) -> Optional[str]:
    if not x or x == "0x":
        return None
    return Web3.to_checksum_address("0x" + x[-40:])

def from_wei(value: int, decimals: int) -> float:
    if decimals <= 0:
        return float(value)
    return value / (10 ** decimals)

# Token and protocol metadata (extendable)
TOKENS: Dict[str, dict] = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {"symbol": "USDC", "decimals": 6, "chain": "ethereum", "type": "token"},
    "0xdac17f958d2ee523a2206206994597c13d831ec7": {"symbol": "USDT", "decimals": 6, "chain": "ethereum", "type": "token"},
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": {"symbol": "WBTC", "decimals": 8, "chain": "ethereum", "type": "token"},
    "0xc36442b4a4522e871399cd717abdd847ab11fe88": {"symbol": "UNI-V3-NPM", "decimals": 0, "chain": "ethereum", "type": "dex"},
    "0x3416cf6c708da44db2624d63ea0aaef7113527c6": {"symbol": "UNI-V3-POOL", "decimals": 0, "chain": "ethereum", "type": "dex"},
    "0x000000000022d473030f116ddee9f6b43ac78ba3": {"symbol": "PERMIT2", "decimals": 0, "chain": "ethereum", "type": "system"},
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": {"symbol": "AAVE-V3-POOL", "decimals": 0, "chain": "ethereum", "type": "lending"},
    "0x98c23e9d8f34fefb1b7bd6a91b7ff122f4e16f5c": {"symbol": "aUSDC", "decimals": 6, "chain": "ethereum", "type": "lending"},
    "0x0000000000000000000000000000000000001010": {"symbol": "MATIC", "decimals": 18, "chain": "polygon", "type": "system"},
}

PROTOCOLS: Dict[str, dict] = {
    "0xc36442b4a4522e871399cd717abdd847ab11fe88": {"protocol": "Uniswap V3", "type": "dex"},
    "0x3416cf6c708da44db2624d63ea0aaef7113527c6": {"protocol": "Uniswap V3", "type": "dex"},
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": {"protocol": "Aave V3", "type": "lending"},
    "0x98c23e9d8f34fefb1b7bd6a91b7ff122f4e16f5c": {"protocol": "Aave V3", "type": "lending"},
    "0x000000000022d473030f116ddee9f6b43ac78ba3": {"protocol": "Permit2", "type": "system"},
}

# === Phase 3: Event Signature Recognition ===
def build_signature_map():
    sigs = {
        "Transfer(address,address,uint256)": ["Transfer", ["address","address","uint256"]],
        "Approval(address,address,uint256)": ["Approval", ["address","address","uint256"]],
        "Swap(address,uint256,uint256,uint256,uint256,address)": ["SwapV2", ["address","uint256","uint256","uint256","uint256","address"]],
        "Sync(uint112,uint112)": ["Sync", ["uint112","uint112"]],
        "Mint(address,uint256,uint256)": ["MintV2", ["address","uint256","uint256"]],
        "Burn(address,uint256,uint256,address)": ["BurnV2", ["address","uint256","uint256","address"]],
        "Swap(address,address,int256,int256,uint160,uint128,int24)": ["SwapV3", ["address","address","int256","int256","uint160","uint128","int24"]],
        "IncreaseLiquidity(address,uint256,uint128,uint256,uint256)": ["IncreaseLiquidity",["address","uint256","uint128","uint256","uint256"]],
        "DecreaseLiquidity(address,uint256,uint128,uint256,uint256)": ["DecreaseLiquidity",["address","uint256","uint128","uint256","uint256"]],
        "Collect(address,address,uint256,uint256)": ["Collect", ["address","address","uint256","uint256"]],
        "Supply(address,address,address,uint256,uint16)": ["Supply", ["address","address","address","uint256","uint16"]],
        "Withdraw(address,address,address,uint256)": ["Withdraw", ["address","address","address","uint256"]],
        "Borrow(address,address,address,uint256,uint256,uint16)": ["Borrow", ["address","address","address","uint256","uint256","uint16"]],
        "Repay(address,address,address,uint256,bool)": ["Repay", ["address","address","address","uint256","bool"]],
        "FlashLoan(address,address,address,uint256,uint256,uint16)": ["FlashLoan",["address","address","address","uint256","uint256","uint16"]],
        "LiquidationCall(address,address,address,uint256,uint256,address,bool)": ["LiquidationCall",["address","address","address","uint256","uint256","address","bool"]],
        "TransferSingle(address,address,address,uint256,uint256)": ["TransferSingle",["address","address","address","uint256","uint256"]],
        "TransferBatch(address,address,address,uint256[],uint256[])": ["TransferBatch",["address","address","address","uint256[]","uint256[]"]],
        "Deposit(address,address,uint256)": ["Deposit", ["address","address","uint256"]],
        "Withdrawal(address,address,uint256,uint256)": ["Withdrawal", ["address","address","uint256","uint256"]],
    }
    topic_to_sig, support_specs = {}, {}
    for proto, (name, inputs) in sigs.items():
        t0 = keccak_sig(proto)
        topic_to_sig[t0] = name
        support_specs[name] = {"proto": proto, "inputs": inputs}
    return topic_to_sig, support_specs

TOPIC_TO_SIG, SUPPORTED_SPECS = build_signature_map()

# === Phase 5: Protocol Identification & Classification ===
def classify_protocol(addr: str) -> Tuple[str, str]:
    a = addr.lower()
    if a in PROTOCOLS:
        info = PROTOCOLS[a]
        return info.get("protocol", "Unknown"), info.get("type", "unknown")
    if a in TOKENS:
        typ = TOKENS[a].get("type", "token")
        return TOKENS[a].get("symbol", "Token"), typ
    return "Unknown", "unknown"

# === Phase 6: Universal Event Decoding ===
def decode_event(log: dict, topic_to_sig: dict = TOPIC_TO_SIG, supported_specs: dict = SUPPORTED_SPECS, tokens: dict = TOKENS) -> dict:
    topics = log.get("topics", [])
    data = log.get("data", "")
    event = {}

    if not topics or len(topics) == 0:
        return {"eventName": "Unknown", "decodedData": None, "note": "Missing topics"}

    topic0 = topics[0].lower()
    event_name = topic_to_sig.get(topic0, "Unknown")

    event["eventName"] = event_name
    event["eventSignature"] = topic0

    spec = supported_specs.get(event_name)
    if spec is None:
        event["decodedData"] = None
        event["note"] = "No ABI spec for event"
        return event

    inputs = spec["inputs"]

    try:
        indexed_count = len(topics) - 1
        indexed_types = inputs[:indexed_count]
        unindexed_types = inputs[indexed_count:]

        indexed_data = []
        for i, typ in enumerate(indexed_types):
            t = topics[i+1]
            if typ == "address":
                indexed_data.append(Web3.to_checksum_address("0x" + t[-40:]))
            elif typ.startswith("uint") or typ.startswith("int"):
                indexed_data.append(int(t, 16))
            else:
                indexed_data.append(t)

        if unindexed_types:
            unindexed_data = decode_abi(unindexed_types, bytes.fromhex(data[2:]))
        else:
            unindexed_data = []

        decoded_params = {}
        for i, val in enumerate(indexed_data):
            decoded_params[f"indexed_param_{i}"] = val
        for i, val in enumerate(unindexed_data):
            decoded_params[f"param_{i}"] = val

        event["decodedData"] = decoded_params
    except Exception as e:
        event["decodedData"] = None
        event["note"] = f"Error decoding: {str(e)}"

    return event

# === Phase 7: Decode All Logs & Aggregate Results ===
def decode_all_logs(
    logs: list,
    addr_to_proto: dict,
    topic_to_sig: dict = TOPIC_TO_SIG,
    supported_specs: dict = SUPPORTED_SPECS,
    tokens: dict = TOKENS
) -> dict:
    events_by_protocol = defaultdict(list)
    event_type_counter = Counter()

    for log in logs:
        addr = (log.get("address") or "").lower()
        proto, ptype = addr_to_proto.get(addr, ("Unknown", "unknown"))

        decoded_event = decode_event(log, topic_to_sig, supported_specs, tokens)
        event_name = decoded_event.get("eventName", "Unknown")
        event_type_counter[event_name] += 1

        ev_entry = {
            "transactionHash": log.get("transactionHash"),
            "blockNumber": log.get("blockNumber"),
            "logIndex": log.get("logIndex"),
            "protocol": proto,
            "protocolType": ptype,
            "contractAddress": addr,
            "eventName": event_name,
            "eventSignature": decoded_event.get("eventSignature"),
            "decodedData": decoded_event.get("decodedData"),
        }
        if decoded_event.get("note"):
            ev_entry["note"] = decoded_event["note"]

        events_by_protocol[ptype].append(ev_entry)

    summary = {
        "totalLogsProcessed": len(logs),
        "totalEventsDecoded": sum(event_type_counter.values()),
        "protocolsIdentified": {k: list(set(ev["protocol"] for ev in v)) for k, v in events_by_protocol.items()},
        "eventTypeDistribution": dict(event_type_counter),
        "processingTimestamp": None
    }

    return {"summary": summary, "eventsByProtocol": dict(events_by_protocol)}
