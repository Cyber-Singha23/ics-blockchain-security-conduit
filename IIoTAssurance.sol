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