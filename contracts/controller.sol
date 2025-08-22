// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal Controller for Dead-Man / Inheritance plans
/// - Creator = plan owner (msg.sender when creating)
/// - Owner can heartbeat() to reset inactivity timer
/// - If inactivity exceeds heartbeatInterval, anyone may call triggerByTimeout()
/// - Guardians can call guardianApprove(); once approvals >= threshold (m), plan releases
/// - Controller calls Executor.release(planId) to instruct asset transfer
/// - Plans and approvals are on-chain and auditable

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IExecutor {
    /// @notice Release assets locked for planId to its beneficiaries
    /// @dev Executor must check calling controller if desired; for MVP keep it simple
    function release(uint256 planId) external;
}

contract Controller is Ownable, ReentrancyGuard {
    uint256 public nextPlanId = 1;

    struct Plan {
        address owner;               // plan creator / wallet whose inactivity is tracked
        address executor;            // address of Executor contract that will release assets
        address[] beneficiaries;     // recipients for release
        uint16[] percents;           // percents in basis points (sum==10000)
        address[] guardians;         // guardian wallets who can collectively trigger
        uint8 m;                     // threshold: required approvals from guardians
        uint48 heartbeatInterval;    // seconds of allowed inactivity
        uint48 lastHeartbeat;        // timestamp of last heartbeat
        bool released;               // whether release has happened
        string metadataURI;          // optional pointer to Greenfield/IPFS encrypted letter
    }

    /// planId => Plan
    mapping(uint256 => Plan) public plans;

    /// planId => guardian address => approved boolean
    mapping(uint256 => mapping(address => bool)) public guardianApprovals;

    /// planId => number of guardian approvals
    mapping(uint256 => uint8) public guardianApprovalCount;

    /// Events
    event PlanCreated(uint256 indexed planId, address indexed owner, address executor);
    event Heartbeat(uint256 indexed planId, address indexed owner, uint48 timestamp);
    event GuardianApproved(uint256 indexed planId, address indexed guardian, uint8 approvals);
    event TriggeredByTimeout(uint256 indexed planId, uint48 timestamp);
    event TriggeredByGuardians(uint256 indexed planId, uint8 approvals, uint48 timestamp);
    event Released(uint256 indexed planId, address indexed executor);

    /// -------------------------
    /// Create / Manage Plan
    /// -------------------------
    /// @notice Create a new plan. Caller becomes plan owner.
    /// @param executor Address of Executor contract (must be set so release() works)
    /// @param beneficiaries Array of beneficiary addresses
    /// @param percents Array of corresponding percents in basis points (sum must equal 10000)
    /// @param guardians Array of guardian addresses (distinct)
    /// @param m Number of guardian approvals required (1..guardians.length)
    /// @param heartbeatInterval Seconds of inactivity allowed before timeout trigger
    /// @param metadataURI Optional URI (Greenfield/IPFS) to encrypted letter
    function createPlan(
        address executor,
        address[] calldata beneficiaries,
        uint16[] calldata percents,
        address[] calldata guardians,
        uint8 m,
        uint48 heartbeatInterval,
        string calldata metadataURI
    ) external returns (uint256) {
        require(executor != address(0), "Executor required");
        require(beneficiaries.length > 0, "Need >0 beneficiaries");
        require(beneficiaries.length == percents.length, "Beneficiaries/percents mismatch");

        uint256 sum;
        for (uint i = 0; i < percents.length; i++) {
            sum += percents[i];
        }
        require(sum == 10000, "Percents must sum to 10000 (100%)");

        require(guardians.length >= m && m > 0, "Invalid guardians/m");

        uint256 planId = nextPlanId++;
        Plan storage p = plans[planId];
        p.owner = msg.sender;
        p.executor = executor;
        p.heartbeatInterval = heartbeatInterval;
        p.lastHeartbeat = uint48(block.timestamp);
        p.released = false;
        p.m = m;
        p.metadataURI = metadataURI;

        // copy arrays
        for (uint i = 0; i < beneficiaries.length; i++) {
            p.beneficiaries.push(beneficiaries[i]);
            p.percents.push(percents[i]);
        }
        for (uint i = 0; i < guardians.length; i++) {
            p.guardians.push(guardians[i]);
        }

        emit PlanCreated(planId, msg.sender, executor);
        return planId;
    }

    /// @notice Owner calls to signal liveness
    function heartbeat(uint256 planId) external {
        Plan storage p = plans[planId];
        require(p.owner != address(0), "Plan not exist");
        require(!p.released, "Plan already released");
        require(msg.sender == p.owner, "Only owner can heartbeat");
        p.lastHeartbeat = uint48(block.timestamp);
        emit Heartbeat(planId, p.lastHeartbeat);
    }

    /// -------------------------
    /// Guardian approvals
    /// -------------------------
    /// @notice Guardian approves triggering release for planId
    function guardianApprove(uint256 planId) external {
        Plan storage p = plans[planId];
        require(p.owner != address(0), "Plan not exist");
        require(!p.released, "Already released");

        // check sender is a guardian
        bool isGuardian = false;
        for (uint i = 0; i < p.guardians.length; i++) {
            if (p.guardians[i] == msg.sender) {
                isGuardian = true;
                break;
            }
        }
        require(isGuardian, "Not a guardian");

        // if not already approved, mark and increment
        if (!guardianApprovals[planId][msg.sender]) {
            guardianApprovals[planId][msg.sender] = true;
            guardianApprovalCount[planId] += 1;
            emit GuardianApproved(planId, msg.sender, guardianApprovalCount[planId]);
        }

        // auto trigger if threshold met
        if (guardianApprovalCount[planId] >= p.m) {
            _release(planId, true);
            emit TriggeredByGuardians(planId, guardianApprovalCount[planId], uint48(block.timestamp));
        }
    }

    /// -------------------------
    /// Timeout trigger
    /// -------------------------
    /// @notice Anyone can call to trigger plan release if owner inactive past heartbeat interval
    function triggerByTimeout(uint256 planId) external nonReentrant {
        Plan storage p = plans[planId];
        require(p.owner != address(0), "Plan not exist");
        require(!p.released, "Plan already released");
        uint48 deadline = p.lastHeartbeat + p.heartbeatInterval;
        require(block.timestamp > deadline, "Not timed out yet");
        emit TriggeredByTimeout(planId, uint48(block.timestamp));
        _release(planId, false);
    }

    /// -------------------------
    /// Internal release
    /// -------------------------
    /// @dev calls executor.release(planId). Executor should manage funds.
    function _release(uint256 planId, bool byGuardians) internal {
        Plan storage p = plans[planId];
        require(!p.released, "Already released");
        p.released = true;

        address exec = p.executor;
        require(exec != address(0), "Executor not set");

        // Call executor
        IExecutor(exec).release(planId);
        emit Released(planId, exec);
    }

    /// -------------------------
    /// Read helpers
    /// -------------------------
    function getPlan(uint256 planId) external view returns (
        address owner,
        address executor,
        address[] memory beneficiaries,
        uint16[] memory percents,
        address[] memory guardians,
        uint8 m,
        uint48 heartbeatInterval,
        uint48 lastHeartbeat,
        bool released,
        string memory metadataURI,
        uint8 approvals
    ) {
        Plan storage p = plans[planId];
        return (
            p.owner,
            p.executor,
            p.beneficiaries,
            p.percents,
            p.guardians,
            p.m,
            p.heartbeatInterval,
            p.lastHeartbeat,
            p.released,
            p.metadataURI,
            guardianApprovalCount[planId]
        );
    }

    /// -------------------------
    /// Admin helpers (owner of Controller)
    /// -------------------------
    /// @notice Emergency: owner can set an executor for a plan (only if not released) — good for hackathon flexibility
    function adminSetExecutor(uint256 planId, address newExecutor) external onlyOwner {
        Plan storage p = plans[planId];
        require(p.owner != address(0), "Plan not exist");
        require(!p.released, "Plan already released");
        p.executor = newExecutor;
    }

    /// @notice Emergency kill — mark plan as released without executing (ONLY for dev/demo)
    function adminMarkReleased(uint256 planId) external onlyOwner {
        Plan storage p = plans[planId];
        require(p.owner != address(0), "Plan not exist");
        p.released = true;
        emit Released(planId, p.executor);
    }
}
