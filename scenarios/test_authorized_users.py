from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
import json
import socket
import struct
from web3 import Web3

GATEWAY_PORT = 5021
HOST = "127.0.0.1"

# Connect to Ganache and load contract config
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
with open(str(ROOT_DIR / "gateway" / "contract_config.json"), "r") as f:
    config = json.load(f)

contract = w3.eth.contract(address=config["contract_address"], abi=config["abi"])
unit_to_address = {int(k): v for k, v in config["accounts"].items() if k.isdigit()}

def send_modbus_request(unit_id, func_code, addr, val, description):
    """Sends a Modbus TCP request through the Edge Gateway conduit."""
    # MBAP Header: TransId=1, ProtoId=0 (On-Chain Gating), Length=6, UnitId, FuncCode, Addr, Val
    frame = struct.pack(">HHHBBHH", 1, 0, 6, unit_id, func_code, addr, val)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, GATEWAY_PORT))
        s.sendall(frame)
        resp = s.recv(1024)
    
    is_exception = (len(resp) >= 8 and (resp[7] & 0x80) != 0)
    status = "BLOCKED (Modbus Exception 0x85)" if is_exception else "ALLOWED (Success)"
    print(f"  [TEST] {description}")
    print(f"         -> Unit ID {unit_id} | Function Code {func_code:02d} | Result: {status}")
    return not is_exception

print("=" * 75)
print("AUTHORIZED USER ACCESS CONTROL TESTING SUITE")
print("=" * 75)

# 1. Inspect initial on-chain state for Unit 1 and Unit 2
print("\n[*] Step 1: Inspecting On-Chain Role Registrations & Initial Trust Scores...")
for u_id in [1, 2]:
    addr = unit_to_address[u_id]
    is_reg, can_write, trust = contract.functions.devices(addr).call()
    role_name = "Engineer (R/W)" if can_write else "HMI Sensor Monitor (R/O)"
    print(f"  -> Unit ID {u_id} ({role_name}): Address={addr} | Registered={is_reg} | CanWrite={can_write} | Trust={trust}")

# 2. Test Unit 1: Engineer (Full Read/Write Access)
print("\n[*] Step 2: Testing Authorized Engineer (Unit ID 1)...")
send_modbus_request(unit_id=1, func_code=3, addr=0, val=1, description="Engineer attempting to READ Boiler Pressure (FC=03)")
send_modbus_request(unit_id=1, func_code=5, addr=0, val=0xFF00, description="Engineer attempting to WRITE / Actuate Relief Valve (FC=05)")

# 3. Test Unit 2: HMI Sensor Monitor (Read-Only Access with Trust Slashing)
print("\n[*] Step 3: Testing Read-Only HMI Monitor (Unit ID 2)...")
send_modbus_request(unit_id=2, func_code=3, addr=0, val=1, description="Monitor attempting valid READ of Boiler Pressure (FC=03)")

print("\n  -> Simulating unauthorized operator action by Monitor...")
send_modbus_request(unit_id=2, func_code=5, addr=0, val=0xFF00, description="Monitor attempting unauthorized VALVE WRITE #1 (FC=05)")

# Check trust score after 1 violation
_, _, trust_after_1 = contract.functions.devices(unit_to_address[2]).call()
print(f"     [TRUST UPDATE] Unit 2 Trust Score after 1st violation: {trust_after_1} / 100")

send_modbus_request(unit_id=2, func_code=5, addr=0, val=0xFF00, description="Monitor attempting unauthorized VALVE WRITE #2 (FC=05)")

# Check trust score after 2 violations (Quarantine threshold reached)
_, _, trust_after_2 = contract.functions.devices(unit_to_address[2]).call()
print(f"     [TRUST UPDATE] Unit 2 Trust Score after 2nd violation: {trust_after_2} / 100 (Quarantined if < 50)")

# 4. Test Post-Quarantine Behavior
print("\n[*] Step 4: Testing Post-Quarantine Access Enforcement...")
send_modbus_request(unit_id=2, func_code=3, addr=0, val=1, description="Quarantined Unit 2 attempting normal READ (FC=03)")

print("\n[+] Authorized User Testing complete!")
