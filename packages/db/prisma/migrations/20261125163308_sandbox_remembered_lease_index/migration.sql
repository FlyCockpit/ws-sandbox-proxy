-- Not transactional: a failure can leave part of this migration applied,
-- and the deploy runner will stop for a person instead of retrying.

CREATE INDEX CONCURRENTLY "sandbox_operation_remembered_lease_idx" ON "sandbox_mutation_operation"("sandboxId", "leaseRevisionAccepted" DESC) WHERE ((kind = ANY (ARRAY['CREATE_SANDBOX'::"SandboxOperationKind", 'RECONNECT_SANDBOX'::"SandboxOperationKind"])) AND ("leaseRevisionAccepted" IS NOT NULL) AND ("leaseTimeoutMs" IS NOT NULL));
