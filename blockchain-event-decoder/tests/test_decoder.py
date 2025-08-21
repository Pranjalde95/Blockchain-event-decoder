import pytest
from web3 import Web3
from src.decoder_core import (
    build_signature_map, classify_protocol, decode_event, TOKENS, PROTOCOLS
)

# Minimal local overrides for testing behavior
TOPIC_TO_SIG, SUPPORTED_SPECS = build_signature_map()

# Dummy event log for Transfer(address,address,uint256)
sample_log = {
    "topics": [
        Web3.keccak(text="Transfer(address,address,uint256)").hex(),
        "0x0000000000000000000000001111111111111111111111111111111111111111",
        "0x0000000000000000000000002222222222222222222222222222222222222222"
    ],
    "data": "0x00000000000000000000000000000000000000000000000000000000000f4240",
    "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
}

def test_classify_protocol_known_token():
    proto, ptype = classify_protocol("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
    assert proto in ("USDC", "USDC Token")
    assert ptype == "token"

def test_classify_protocol_unknown():
    proto, ptype = classify_protocol("0x0000000000000000000000000000000000000000")
    assert proto == "Unknown"
    assert ptype == "unknown"

def test_decode_event_transfer():
    decoded = decode_event(sample_log, TOPIC_TO_SIG, SUPPORTED_SPECS, TOKENS)
    assert decoded["eventName"] == "Transfer"
    assert decoded["decodedData"]["indexed_param_0"] == Web3.to_checksum_address("0x1111111111111111111111111111111111111111")
    assert decoded["decodedData"]["indexed_param_1"] == Web3.to_checksum_address("0x2222222222222222222222222222222222222222")
    assert decoded["decodedData"]["param_0"] == 1000000

def test_decode_event_missing_topics():
    decoded = decode_event({"topics": [], "data": "0x", "address": ""}, TOPIC_TO_SIG, SUPPORTED_SPECS, TOKENS)
    assert decoded["eventName"] == "Unknown"
    assert decoded["note"] == "Missing topics"

def test_decode_event_unknown_signature():
    log_unknown = dict(sample_log)
    log_unknown["topics"] = ["0x" + "00"*32]
    decoded = decode_event(log_unknown, TOPIC_TO_SIG, SUPPORTED_SPECS, TOKENS)
    assert decoded["eventName"] == "Unknown"
