// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditAttestation} from "../AuditAttestation.sol";

contract AuditAttestationTest is Test {
    AuditAttestation att;
    address owner = address(this);
    address auditor = address(0xA11CE);
    address stranger = address(0xBAD);

    function setUp() public { att = new AuditAttestation(); }

    function test_OwnerIsAttesterByDefault() public view {
        assertTrue(att.isAttester(owner));
        assertEq(att.owner(), owner);
    }

    function test_AttestAndVerify() public {
        bytes32 h = keccak256("report-1");
        uint256 id = att.attest(address(0x1234), h, AuditAttestation.Verdict.Clean, "ipfs://x");
        assertEq(id, 1);
        (bool found, AuditAttestation.Attestation memory a) = att.verify(h);
        assertTrue(found);
        assertEq(a.reportHash, h);
        assertEq(uint(a.verdict), uint(AuditAttestation.Verdict.Clean));
        assertEq(att.count(), 1);
    }

    function test_NonAttesterCannotAttest() public {
        vm.prank(stranger);
        vm.expectRevert(AuditAttestation.NotAttester.selector);
        att.attest(address(0x1), keccak256("r"), AuditAttestation.Verdict.Clean, "");
    }

    function test_DuplicateHashReverts() public {
        bytes32 h = keccak256("dup");
        att.attest(address(0x1), h, AuditAttestation.Verdict.IssuesFound, "");
        vm.expectRevert(AuditAttestation.AlreadyAttested.selector);
        att.attest(address(0x2), h, AuditAttestation.Verdict.Clean, "");
    }

    function test_ZeroHashReverts() public {
        vm.expectRevert(AuditAttestation.ZeroHash.selector);
        att.attest(address(0x1), bytes32(0), AuditAttestation.Verdict.Clean, "");
    }

    function test_TwoStepOwnership() public {
        att.transferOwnership(auditor);
        assertEq(att.owner(), owner);              // aún no toma efecto
        assertEq(att.pendingOwner(), auditor);
        vm.prank(auditor);
        att.acceptOwnership();
        assertEq(att.owner(), auditor);            // ahora sí
        assertEq(att.pendingOwner(), address(0));
    }

    function test_OnlyPendingCanAccept() public {
        att.transferOwnership(auditor);
        vm.prank(stranger);
        vm.expectRevert(AuditAttestation.NotOwner.selector);
        att.acceptOwnership();
    }

    function test_SetAttester() public {
        att.setAttester(auditor, true);
        vm.prank(auditor);
        att.attest(address(0x1), keccak256("byauditor"), AuditAttestation.Verdict.Clean, "");
        assertEq(att.count(), 1);
    }
}
