## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The failure mode or audit finding this addresses. -->

## Verification

- [ ] `npm run version:check`
- [ ] `npm run typecheck`
- [ ] relevant test subset (list files)
- [ ] full `npm test` if the change touches shared rules or engines

## Risk and rollback

<!-- Fail-closed behavior changes? New external engine? Migration needed? -->

## Checklist

- [ ] Tests cover the new behavior, including the failure path
- [ ] No secrets, live tokens, or machine-specific paths
- [ ] Docs updated when behavior or prerequisites changed
