import json
import argparse
from typing import Tuple
from src.decoder_core import (
    TOKENS, PROTOCOLS, build_signature_map, classify_protocol,
    decode_all_logs
)

def build_addr_to_proto(logs):
    addr_to_proto_type = {}
    for lg in logs:
        a = (lg.get("address") or "").lower()
        if a and a not in addr_to_proto_type:
            proto, ptype = classify_protocol(a)
            addr_to_proto_type[a] = (proto, ptype)
    return addr_to_proto_type

def main():
    parser = argparse.ArgumentParser(description="Multi-Protocol Blockchain Event Log Decoder")
    parser.add_argument("-i", "--input", default="sample.json", help="Path to input JSON file")
    parser.add_argument("-o", "--out", default="decoded_events_output.json", help="Path to write decoded output JSON")
    parser.add_argument("-n", "--limit", type=int, default=None, help="Only process first N logs (debugging)")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        raw = json.load(f)

    logs = raw["logs"] if isinstance(raw, dict) and "logs" in raw else raw
    if args.limit is not None:
        logs = logs[:args.limit]

    addr_to_proto_type = build_addr_to_proto(logs)

    result = decode_all_logs(logs, addr_to_proto_type)

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    # Print concise summary
    print(json.dumps(result["summary"], indent=2))

if __name__ == "__main__":
    main()
