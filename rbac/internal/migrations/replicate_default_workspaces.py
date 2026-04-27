import itertools
import logging
from typing import Optional

from management.atomic_transactions import atomic_with_retry
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    RelationReplicator,
    ReplicationEventType,
    WorkspaceEventStream,
)
from management.workspace.model import Workspace
from management.workspace.utils.event import make_workspace_event


@atomic_with_retry(retries=3)
def _do_replicate_batch(replicator: RelationReplicator, raw_workspaces: list[Workspace]) -> int:
    """Replicates a batch of workspaces and returns the number actually replicated."""
    if len(raw_workspaces) == 0:
        return 0

    workspaces = list(
        Workspace.objects.filter(type=Workspace.Types.DEFAULT)
        .filter(pk__in=(w.pk for w in raw_workspaces))
        .select_related("tenant")
        .select_for_update(of=["self"])
    )

    for workspace in workspaces:
        replicator.replicate_workspace(
            make_workspace_event(workspace=workspace, event_type=ReplicationEventType.CREATE_WORKSPACE),
            WorkspaceEventStream.BULK,
        )

    return len(workspaces)


logger = logging.getLogger(__name__)


def replicate_default_workspaces(replicator: Optional[RelationReplicator] = None, limit: Optional[int] = None):
    if replicator is None:
        replicator = OutboxReplicator()

    query = Workspace.objects.filter(type=Workspace.Types.DEFAULT)
    total_count = query.count()

    if limit is not None:
        query = query[:limit]
        expected_count = min(total_count, limit)
    else:
        expected_count = total_count

    logger.info(f"About to replicate ~{expected_count} (out of a total of ~{total_count}) default workspaces.")

    actual_count = 0
    error = False

    for raw_batch in itertools.batched(query, 500):
        try:
            actual_count += _do_replicate_batch(replicator, list(raw_batch))
            logger.info(f"Replicated {actual_count}/~{expected_count} default workspaces.")
        except Exception:
            logger.error("Failed to replicate batch of default workspaces", exc_info=True)
            error = True

    logger.info(f"Replicated a total of {actual_count} default workspaces.")

    if error:
        raise RuntimeError("Failed to replicate all default workspaces")
