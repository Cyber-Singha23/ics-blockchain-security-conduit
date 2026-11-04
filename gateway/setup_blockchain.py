from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
import json
import solcx
from web3 import Web3

# 1. Connect to local Ganache instance
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
assert w3.is_connected(), "Failed to connect to Ganache on 127.0.0.1:8545"

print("[*] Connected to Ganache. Installing Solidity compiler 0.8.20...")
solcx.install_solc("0.8.20")
solcx.set_solc_version("0.8.20")

# 2. Solidity Smart Contract combining Access Control, Trust, and Merkle Integrity
contract_source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IIoTAssurance {
    struct Device {
        bool isRegistered;
        bool canWriteActuator;
        uint256 trustScore;
    }

    mapping(address => Device) public devices;
    bytes32[] public merkleRoots;
    uint256 public constant TRUST_THRESHOLD = 50;

    event AccessEvaluated(address indexed device, uint8 funcCode, bool granted, uint256 newTrust);
    event MerkleRootAnchored(uint256 indexed batchId, bytes32 merkleRoot, uint256 timestamp);

    function registerDevice(address _dev, bool _canWrite) public {
        devices[_dev] = Device(true, _canWrite, 100);
    }

    // Synchronous on-chain evaluation + dynamic trust slashing
    function evaluateAccess(address _dev, uint8 _modbusFuncCode) public returns (bool) {
        Device storage d = devices[_dev];
        if (!d.isRegistered || d.trustScore < TRUST_THRESHOLD) {
            emit AccessEvaluated(_dev, _modbusFuncCode, false, d.trustScore);
            return false;
        }

        // Function codes 5 (Write Single Coil) & 6 (Write Single Register) require write privilege
        if ((_modbusFuncCode == 5 || _modbusFuncCode == 6) && !d.canWriteActuator) {
            if (d.trustScore >= 30) {
                d.trustScore -= 30;
            } else {
                d.trustScore = 0;
            }
            emit AccessEvaluated(_dev, _modbusFuncCode, false, d.trustScore);
            return false;
        }

        emit AccessEvaluated(_dev, _modbusFuncCode, true, d.trustScore);
        return true;
    }

    // Fast read-only view for Edge-Cached verification (RQ1 countermeasure)
    function checkPermissionView(address _dev, uint8 _modbusFuncCode) public view returns (bool, uint256) {
        Device memory d = devices[_dev];
        if (!d.isRegistered || d.trustScore < TRUST_THRESHOLD) return (false, d.trustScore);
        if ((_modbusFuncCode == 5 || _modbusFuncCode == 6) && !d.canWriteActuator) return (false, d.trustScore);
        return (true, d.trustScore);
    }

    // Merkle root anchoring for tamper-evident sensor logs (RQ3 support)
    function anchorMerkleRoot(bytes32 _root) public {
        merkleRoots.push(_root);
        emit MerkleRootAnchored(merkleRoots.length - 1, _root, block.timestamp);
    }

    function getMerkleRoot(uint256 _batchId) public view returns (bytes32) {
        return merkleRoots[_batchId];
    }

    function getMerkleBatchCount() public view returns (uint256) {
        return merkleRoots.length;
    }
}
"""

with open(str(ROOT_DIR / "contracts" / "IIoTAssurance.sol"), "w") as f:
    f.write(contract_source.strip())

print("[*] Compiling IIoTAssurance.sol...")
compiled = solcx.compile_source(contract_source, output_values=["abi", "bin"])
contract_id, contract_interface = compiled.popitem()
abi = contract_interface["abi"]
bytecode = contract_interface["bin"]

# 3. Deploy contract using Account[0] (Gateway Admin)
admin_acct = w3.eth.accounts[0]
engineer_acct = w3.eth.accounts[1]   # Unit ID 1: Authorized Engineer (Read + Write)
hmi_sensor_acct = w3.eth.accounts[2] # Unit ID 2: Compromised/Read-Only Monitor (Read Only)
rogue_acct = w3.eth.accounts[3]      # Unit ID 3: Unregistered Attacker

IIoTContract = w3.eth.contract(abi=abi, bytecode=bytecode)
print("[*] Deploying contract to Ganache (waiting for 1s block time)...")
tx_hash = IIoTContract.constructor().transact({"from": admin_acct})
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_address = receipt.contractAddress
print(f"[+] Contract deployed at: {contract_address}")

contract = w3.eth.contract(address=contract_address, abi=abi)

# 4. Register Industrial Devices
print("[*] Registering ICS roles on-chain...")
tx1 = contract.functions.registerDevice(engineer_acct, True).transact({"from": admin_acct})
tx2 = contract.functions.registerDevice(hmi_sensor_acct, False).transact({"from": admin_acct})
w3.eth.wait_for_transaction_receipt(tx1)
w3.eth.wait_for_transaction_receipt(tx2)

print(f"    -> Unit 1 (Engineer - R/W):   {engineer_acct} | Trust: 100")
print(f"    -> Unit 2 (Monitor - R/O):    {hmi_sensor_acct} | Trust: 100")
print(f"    -> Unit 3 (Rogue - Unreg):    {rogue_acct} | Trust: 0")

config = {
    "contract_address": contract_address,
    "abi": abi,
    "accounts": {
        "admin": admin_acct,
        "1": engineer_acct,
        "2": hmi_sensor_acct,
        "3": rogue_acct
    }
}
with open(str(ROOT_DIR / "gateway" / "contract_config.json"), "w") as f:
    json.dump(config, f, indent=2)

print("[+] Saved contract_config.json successfully!")
