"""
HAIA-Overwatch v1.0 - Execution Graph Engine

Tracks operation flow through the Overwatch inspection pipeline.
Records role assignments, platform dispatches, navigation, and decisions.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import time
from typing import Dict, List

from .models import ExecutionGraph, GraphEdge, GraphNode, TransactionRecord
from .structured_logger import get_logger, sanitize_log_value as _sanitize_log

logger = get_logger(__name__)


class ExecutionGraphEngine:
    """Records and manages execution graphs for transaction sequences.

    Tracks the flow of content through role assignments, dispatches,
    platform responses, navigator routing, synthesis, checkpoints,
    and human decisions.
    """

    def __init__(self):
        """Initialize ExecutionGraphEngine."""
        self._graphs: Dict[str, ExecutionGraph] = {}
        self._last_node: Dict[str, GraphNode] = {}

    def record_role_assignment(self, op_id: str, role: str, content_hash: str) -> str:
        """Record a role assignment node.

        Args:
            op_id: Operation/operator identifier
            role: RECCLIN role assigned
            content_hash: SHA-256 hash of content

        Returns:
            Node ID of the created node
        """
        node = GraphNode(
            node_type="role_assignment",
            timestamp=time.time(),
            content_hash=content_hash,
            metadata={"role": role}
        )
        self._add_node(op_id, node)
        return node.node_id

    def record_dispatch(self, op_id: str, platforms: List[str], content_hash: str) -> str:
        """Record a platform dispatch node.

        Args:
            op_id: Operation identifier
            platforms: List of platform IDs dispatched to
            content_hash: SHA-256 hash of dispatched content

        Returns:
            Node ID of the created node
        """
        node = GraphNode(
            node_type="dispatch",
            timestamp=time.time(),
            content_hash=content_hash,
            metadata={"platforms": platforms}
        )
        self._add_node(op_id, node)
        return node.node_id

    def record_response(self, op_id: str, platform_id: str, content_hash: str) -> str:
        """Record a platform response node.

        Args:
            op_id: Operation identifier
            platform_id: Platform providing response
            content_hash: SHA-256 hash of response content

        Returns:
            Node ID of the created node
        """
        node = GraphNode(
            node_type="response",
            timestamp=time.time(),
            content_hash=content_hash,
            metadata={"platform_id": platform_id}
        )
        self._add_node(op_id, node)
        return node.node_id

    def record_navigator_routing(self, op_id: str, content_hash: str) -> str:
        """Record a navigator routing decision node.

        Args:
            op_id: Operation identifier
            content_hash: SHA-256 hash of routing decision

        Returns:
            Node ID of the created node
        """
        node = GraphNode(
            node_type="navigator_routing",
            timestamp=time.time(),
            content_hash=content_hash
        )
        self._add_node(op_id, node)
        return node.node_id

    def record_navigator_synthesis(self, op_id: str, content_hash: str) -> str:
        """Record a navigator synthesis node.

        Args:
            op_id: Operation identifier
            content_hash: SHA-256 hash of synthesized content

        Returns:
            Node ID of the created node
        """
        node = GraphNode(
            node_type="navigator_synthesis",
            timestamp=time.time(),
            content_hash=content_hash
        )
        self._add_node(op_id, node)
        return node.node_id

    def record_checkpoint(self, op_id: str, content_hash: str) -> str:
        """Record a checkpoint node (verification gate).

        Args:
            op_id: Operation identifier
            content_hash: SHA-256 hash of checkpoint state

        Returns:
            Node ID of the created node
        """
        node = GraphNode(
            node_type="checkpoint",
            timestamp=time.time(),
            content_hash=content_hash
        )
        self._add_node(op_id, node)
        return node.node_id

    def record_human_decision(self, op_id: str, decision: str, content_hash: str) -> str:
        """Record a human decision node.

        Args:
            op_id: Operation identifier
            decision: Human decision description
            content_hash: SHA-256 hash of decision context

        Returns:
            Node ID of the created node
        """
        node = GraphNode(
            node_type="human_decision",
            timestamp=time.time(),
            content_hash=content_hash,
            metadata={"decision": decision}
        )
        self._add_node(op_id, node)
        return node.node_id

    def record_transaction(self, txn: TransactionRecord) -> None:
        """Convenience method: create graph nodes for a transaction.

        Creates:
        - role_assignment node
        - dispatch node (one per platform)
        - response node (one per platform response)

        Args:
            txn: TransactionRecord to record
        """
        op_id = txn.operator_id

        # Ensure graph exists
        if op_id not in self._graphs:
            self._graphs[op_id] = ExecutionGraph(transaction_ids=[txn.transaction_id])
        else:
            if txn.transaction_id not in self._graphs[op_id].transaction_ids:
                self._graphs[op_id].transaction_ids.append(txn.transaction_id)

        # Record role assignment
        self.record_role_assignment(op_id, txn.recclin_role.value, txn.prompt_hash)

        # Record dispatch to platforms
        self.record_dispatch(op_id, txn.platforms_dispatched, txn.prompt_hash)

        # Record responses from each platform
        for response in txn.responses:
            self.record_response(op_id, response.platform_id, response.response_hash)

    def get_sequence(self, op_id: str) -> List[str]:
        """Get the node type sequence for an operator.

        Returns nodes in chronological order.

        Args:
            op_id: Operation identifier

        Returns:
            List of node type strings in temporal order
        """
        if op_id not in self._graphs:
            return []
        return self._graphs[op_id].get_node_sequence()

    def prune(self, op_id: str) -> None:
        """Remove an operator's graph on session close.

        Args:
            op_id: Operation identifier to remove
        """
        if op_id in self._graphs:
            del self._graphs[op_id]
            logger.debug("Pruned execution graph for operator %s",
                         _sanitize_log(op_id))
        if op_id in self._last_node:
            del self._last_node[op_id]

    def prune_stale(self, max_age_seconds: float = 7200.0) -> int:
        """Remove operator graphs with no activity beyond max_age_seconds.

        Prevents unbounded memory growth from accumulated operator graphs.

        Args:
            max_age_seconds: Maximum age in seconds before pruning (default: 2 hours)

        Returns:
            Number of stale graphs pruned
        """
        now = time.time()
        stale_ops = []

        for op_id, graph in self._graphs.items():
            # Use the last node's timestamp as "last activity"
            last_node = self._last_node.get(op_id)
            if last_node:
                last_activity = last_node.timestamp
            else:
                last_activity = graph.created_timestamp

            if (now - last_activity) > max_age_seconds:
                stale_ops.append(op_id)

        for op_id in stale_ops:
            self.prune(op_id)

        if stale_ops:
            logger.info("Pruned %d stale execution graphs", len(stale_ops))

        return len(stale_ops)

    def _add_node(self, op_id: str, node: GraphNode) -> None:
        """Internal: add node to graph and create edge from previous node.

        Args:
            op_id: Operation identifier
            node: GraphNode to add
        """
        # Ensure graph exists
        if op_id not in self._graphs:
            self._graphs[op_id] = ExecutionGraph()

        # Add node
        self._graphs[op_id].add_node(node)

        # Create edge from previous node if it exists
        if op_id in self._last_node:
            prev_node = self._last_node[op_id]
            edge = GraphEdge(
                source_node_id=prev_node.node_id,
                target_node_id=node.node_id,
                content_hash=node.content_hash,
                timestamp=time.time()
            )
            self._graphs[op_id].add_edge(edge)

        # Update last node reference
        self._last_node[op_id] = node
