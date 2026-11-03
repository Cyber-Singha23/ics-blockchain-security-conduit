import csv
import hashlib
import json
import os
import socket
import struct
import time
from web3 import Web3

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 5021
PLC_HOST = "127.0.0.1"
PLC_PORT = 5020
LOG_FILE = "sensor_logs.csv"

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
with open("contract_config.json", "r") as f:
    config = json.load(f)

contract = w3.eth.contract(address=config["contract_address"], abi=config["abi"])
admin_acct = config["accounts"]["admin"]
unit_to_address = {int(k): v for k, v in config["accounts"].items() if k.isdigit()}

edge_cache = {}
sensor_batch = []
batch_counter = 0

def sync_edge_cache():
    """Synchronizes local edge memory with blockchain state."""
    for unit_id, addr in unit_to_address.items():
        is_reg, can_write, trust = contract.functions.devices(addr).call()
        can_read = is_reg and (trust >= 50)
        edge_cache[unit_id] = {
            "address": addr,
            "can_read": can_read,
            "can_write": can_read and can_write,
            "trust": trust
        }

def compute_merkle_root(leaves):
    """Computes binary SHA-256 Merkle root over a batch of sensor log strings."""
    hashes = [hashlib.sha256(leaf.encode("utf-8")).digest() for leaf in leaves]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        hashes = [
            hashlib.sha256(hashes[i] + hashes[i + 1]).digest()
            for i in range(0, len(hashes), 2)
        ]
    return hashes[0]

def trigger_plc_failsafe():
    """RQ3 Automated Controller Response: Immediately opens PLC Relief Valve (Coil 0 = 1)."""
    print("[GATEWAY-RQ3] !!! CRITICAL SECURITY ALERT: Triggering Automated PLC Fail-Safe (Opening Relief Valve Coil 0) !!!")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as plc_sock:
        plc_sock.connect((PLC_HOST, PLC_PORT))
        frame = struct.pack(">HHHBBHH", 999, 0, 6, 0, 5, 0, 0xFF00)
        plc_sock.sendall(frame)
        plc_sock.recv(1024)

def forward_to_plc(frame):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as plc_sock:
        plc_sock.connect((PLC_HOST, PLC_PORT))
        plc_sock.sendall(frame)
        return plc_sock.recv(1024)

def record_sensor_reading(pressure_val):
    global sensor_batch, batch_counter
    row_id = batch_counter * 8 + len(sensor_batch)
    entry_str = f"id={row_id}|reg=0|psi={pressure_val}"
    sensor_batch.append((row_id, pressure_val, entry_str))

    if len(sensor_batch) == 8:
        leaves = [item[2] for item in sensor_batch]
        root_bytes = compute_merkle_root(leaves)
        tx = contract.functions.anchorMerkleRoot(root_bytes).transact({"from": admin_acct})
        w3.eth.wait_for_transaction_receipt(tx)
        print(f"[GATEWAY-INTEGRITY] Anchored Merkle Root for Batch #{batch_counter}: 0x{root_bytes.hex()[:16]}...")

        file_exists = os.path.isfile(LOG_FILE)
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["batch_id", "row_id", "pressure_psi", "canonical_string"])
            for r_id, psi, c_str in sensor_batch:
                writer.writerow([batch_counter, r_id, psi, c_str])

        sensor_batch = []
        batch_counter += 1

def handle_client_request(data):
    if len(data) < 12:
        return b""
    trans_id, proto_id, length, unit_id, func_code, addr, val = struct.unpack(">HHHBBHH", data[:12])
    dev_addr = unit_to_address.get(unit_id, "0x0000000000000000000000000000000000000000")

    # Mode 1: Edge-Cached Fast Verification (RQ1 Solution)
    if proto_id == 1:
        info = edge_cache.get(unit_id)
        allowed = False
        if info:
            allowed = info["can_write"] if func_code in (5, 6) else info["can_read"]
        if not allowed:
            if func_code in (5, 6):
                tx = contract.functions.evaluateAccess(dev_addr, func_code).transact({"from": admin_acct})
                w3.eth.wait_for_transaction_receipt(tx)
                sync_edge_cache()
                cur_trust = edge_cache.get(unit_id, {}).get("trust", 0)
                print(f"[GATEWAY-ACL] Unit {unit_id} | FC={func_code:02d} | Granted=False | Trust Score={cur_trust} (Blocked at Conduit)")
                if cur_trust < 50 and unit_id in (1, 2):
                    trigger_plc_failsafe()
            return struct.pack(">HHHBBB", trans_id, 0, 3, unit_id, func_code | 0x80, 1)

    # Mode 0: Synchronous On-Chain Transaction Gating
    else:
        tx = contract.functions.evaluateAccess(dev_addr, func_code).transact({"from": admin_acct})
        receipt = w3.eth.wait_for_transaction_receipt(tx)
        logs = contract.events.AccessEvaluated().process_receipt(receipt)
        granted = logs[0]["args"]["granted"] if logs else False
        new_trust = logs[0]["args"]["newTrust"] if logs else 0
        sync_edge_cache()

        print(f"[GATEWAY-ACL] Unit {unit_id} | FC={func_code:02d} | Granted={granted} | Trust Score={new_trust}")
        if not granted:
            if new_trust < 50 and unit_id in (1, 2):
                print(f"[GATEWAY-TRUST] Unit {unit_id} trust dropped below threshold ({new_trust} < 50)! Node quarantined.")
                trigger_plc_failsafe()
            return struct.pack(">HHHBBB", trans_id, 0, 3, unit_id, func_code | 0x80, 1)

    clean_frame = struct.pack(">HHHBBHH", trans_id, 0, length, unit_id, func_code, addr, val)
    plc_resp = forward_to_plc(clean_frame)

    if func_code == 3 and len(plc_resp) >= 11:
        _, _, _, _, _, _, pressure_val = struct.unpack(">HHHBBBH", plc_resp[:11])
        if proto_id == 2:
            record_sensor_reading(pressure_val)

    return plc_resp

def start_gateway():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    sync_edge_cache()
    print(f"[*] Edge Blockchain Security Gateway listening on {GATEWAY_HOST}:{GATEWAY_PORT}...")
    print(f"[*] Forwarding verified Modbus traffic to PLC at {PLC_HOST}:{PLC_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((GATEWAY_HOST, GATEWAY_PORT))
        s.listen(5)
        while True:
            conn, _ = s.accept()
            with conn:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    resp = handle_client_request(data)
                    conn.sendall(resp)

if __name__ == "__main__":
    start_gateway()
