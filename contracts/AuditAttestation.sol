// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AuditAttestation
/// @author Nawel · OpenClaw
/// @notice Registro on-chain y verificable de atestaciones de revisión de seguridad. El auditor autorizado
///         publica el hash del informe entregado + un veredicto; cualquiera puede verificar después que un
///         informe dado coincide con una atestación on-chain (prueba de integridad + procedencia + fecha).
/// @dev    Sin llamadas externas (no reentrancy). Control de acceso por lista de attesters. Errores custom
///         para ahorrar gas. Pensado para desplegar en testnet (Base/OP Sepolia) para el submission AgentFi.
contract AuditAttestation {
    enum Verdict { Clean, IssuesFound, CandidatesPending }

    struct Attestation {
        address subject;     // protocolo/owner del código auditado (informativo)
        bytes32 reportHash;  // keccak256/sha256 del informe entregado (bytes del .md/.pdf)
        Verdict verdict;
        uint64  timestamp;
        string  uri;         // opcional: enlace al informe (ipfs/https)
    }

    address public owner;
    address public pendingOwner;                    // ownership en 2 pasos (evita bloqueo por typo)
    mapping(address => bool) public isAttester;     // auditores autorizados a atestar
    Attestation[] public attestations;
    mapping(bytes32 => uint256) public idByHash;    // reportHash => id (1-based; 0 = inexistente)

    event AttesterSet(address indexed attester, bool allowed);
    event Attested(uint256 indexed id, address indexed subject, bytes32 indexed reportHash, Verdict verdict, string uri);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);

    error NotOwner();
    error NotAttester();
    error ZeroHash();
    error ZeroAddress();
    error AlreadyAttested();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        isAttester[msg.sender] = true;
        emit AttesterSet(msg.sender, true);
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Autoriza o revoca a un auditor para atestar.
    function setAttester(address attester, bool allowed) external onlyOwner {
        if (attester == address(0)) revert ZeroAddress();
        isAttester[attester] = allowed;
        emit AttesterSet(attester, allowed);
    }

    /// @notice Paso 1: el owner actual nomina un nuevo owner (no toma efecto hasta que lo acepte).
    function transferOwnership(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        pendingOwner = to;
        emit OwnershipTransferStarted(owner, to);
    }

    /// @notice Paso 2: el owner nominado acepta, completando la transferencia. Evita el bloqueo por typo.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    /// @notice Registra una atestación para un informe entregado. Idempotente por reportHash.
    /// @return id Identificador 1-based de la atestación.
    function attest(address subject, bytes32 reportHash, Verdict verdict, string calldata uri)
        external
        returns (uint256 id)
    {
        if (!isAttester[msg.sender]) revert NotAttester();
        if (reportHash == bytes32(0)) revert ZeroHash();
        if (idByHash[reportHash] != 0) revert AlreadyAttested();

        attestations.push(Attestation({
            subject: subject,
            reportHash: reportHash,
            verdict: verdict,
            timestamp: uint64(block.timestamp),
            uri: uri
        }));
        id = attestations.length; // 1-based
        idByHash[reportHash] = id;
        emit Attested(id, subject, reportHash, verdict, uri);
    }

    /// @notice Verifica si un hash de informe fue atestado on-chain.
    /// @return found True si existe una atestación para ese hash.
    /// @return a     La atestación (vacía si no existe).
    function verify(bytes32 reportHash) external view returns (bool found, Attestation memory a) {
        uint256 idx = idByHash[reportHash];
        if (idx == 0) return (false, a);
        return (true, attestations[idx - 1]);
    }

    /// @notice Número total de atestaciones registradas.
    function count() external view returns (uint256) {
        return attestations.length;
    }
}
