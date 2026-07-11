// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {AuditAttestation} from "../AuditAttestation.sol";

/// @notice Deploy AuditAttestation. Usage:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --private-key $PRIVATE_KEY
contract Deploy is Script {
    function run() external returns (AuditAttestation att) {
        vm.startBroadcast();
        att = new AuditAttestation();
        vm.stopBroadcast();
        console2.log("AuditAttestation deployed at:", address(att));
    }
}
