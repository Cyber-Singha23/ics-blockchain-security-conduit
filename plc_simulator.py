import socket
import struct
import random

HOST = "127.0.0.1"
PORT = 5020  # Direct Unsecured PLC Modbus TCP Port

# Simulated PLC State
holding_registers = {0: 75}  # Register 0: Boiler Pressure (PSI)
coils = {0: 0}               # Coil 0: Emergency Relief Valve (0=Closed, 1=Open/Safe State)

def handle_modbus_frame(data):
    if len(data) < 12:
        return b""
    trans_id, proto_id, length, unit_id, func_code, addr, val = struct.unpack(">HHHBBHH", data[:12])

    # FC 03: Read Holding Registers
    if func_code == 3:
        # Simulate slight boiler pressure fluctuation around 75 PSI
        current_pressure = holding_registers.get(addr, 75) + random.choice([-1, 0, 1])
        current_pressure = max(70, min(80, current_pressure))
        holding_registers[addr] = current_pressure
        # MBAP Header (7 bytes) + FC (1 byte) + ByteCount (1 byte) + RegVal (2 bytes)
        return struct.pack(">HHHBBBH", trans_id, proto_id, 5, unit_id, 3, 2, current_pressure)

    # FC 05: Write Single Coil (e.g., Relief Valve actuation)
    elif func_code == 5:
        coil_state = 1 if val > 0 else 0
        coils[addr] = coil_state
        
        # Differentiate source so report logs & terminal output are unambiguous
        if unit_id == 0:
            source_desc = "ADMIN GATEWAY (Automated Fail-Safe Defense)"
            status_str = "OPEN (FAIL-SAFE ACTIVATED)" if coil_state == 1 else "CLOSED (NORMAL)"
        elif unit_id in (1, 2):
            source_desc = f"AUTHORIZED USER (Unit {unit_id})"
            status_str = "OPEN" if coil_state == 1 else "CLOSED"
        else:
            source_desc = f"ROGUE ATTACKER (Unauthenticated Unit {unit_id} - BREACH!)"
            status_str = "OPEN (MALICIOUSLY OVERRIDDEN)" if coil_state == 1 else "CLOSED"

        print(f"[PLC-LOG] Coil {addr} written by {source_desc}: Relief Valve is now {status_str}")
        return data[:12]  # Echo standard Modbus FC05 confirmation

    # FC 06: Write Single Register (e.g., Setpoint modification)
    elif func_code == 6:
        holding_registers[addr] = val
        print(f"[PLC-LOG] REGISTER {addr} WRITTEN BY UNIT {unit_id}: New Value = {val} PSI")
        return data[:12]

    # Unsupported Function Code -> Return Modbus Exception 0x01
    return struct.pack(">HHHBBB", trans_id, proto_id, 3, unit_id, func_code | 0x80, 1)

def start_plc():
    print(f"[*] Starting Industrial Boiler PLC Simulator (Modbus TCP) on {HOST}:{PORT}...")
    print(f"    -> Holding Register 0 (Boiler Pressure): {holding_registers[0]} PSI")
    print(f"    -> Coil 0 (Emergency Relief Valve):      {coils[0]} (Closed)")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        while True:
            conn, _ = s.accept()
            with conn:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    resp = handle_modbus_frame(data)
                    conn.sendall(resp)

if __name__ == "__main__":
    start_plc()
