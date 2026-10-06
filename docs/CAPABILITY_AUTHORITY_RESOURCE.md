# Capability authority: privileged rights belong to the authority office (issue #266)

Answers the known limit in omega `docs/r16-operator-control.md` ("the halt right is the epoch right").

## Rule

In `native/capability/aienos_capability.c`, `auth_use` is the single gate for every privileged
authority operation: mint (root), revoke, reclaim, clock advance and epoch bump. It now also
requires the presented entry's resource to be `AIENOS_CAP_RES_AUTHORITY`. A refusal returns
`AIENOS_CAP_ERR_RESOURCE`.

A capability may still carry a privileged right on another resource, for example the operator
CONTROL resource with the epoch right used as the halt right. `aienos_cap_validate` still accepts it
for that resource, so operator stop, status and resume keep working. The authority operations
simply no longer accept it, so it can never step the epoch, move the clock, revoke, reclaim or mint.

## Why the resource and not a new right

No accepted ADR or spec in this repository defines a distinct halt or stop right, and adding one
would change the rights layout the reaction world links against unchanged. The resource check closes
the hole at the one gate, with no ABI change. Delegation is untouched: privileged rights still
cannot be delegated.

## Evidence

`make test` in `native/capability`: `control_resource_capability_cannot_operate_the_authority`
(negative: epoch, clock, revoke, reclaim, mint refused; regression: CONTROL-resource validate and the
real office still work). `make mutants`: `privileged_right_ignores_resource` removes the check and
the tests must kill it.

## Pin note

The `aienos.lock` pin in other repositories moves only through a new named candidate, so omega keeps
its limit note until it adopts one.
