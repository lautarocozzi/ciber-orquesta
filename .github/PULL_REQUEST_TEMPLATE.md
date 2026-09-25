<!--
  Every PR MUST link an approved issue. No exceptions.
  The linked issue MUST have the `status:approved` label.
-->

Closes #<issue-number>

## PR Type

Check exactly ONE:

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation only
- [ ] Code refactoring
- [ ] Maintenance/tooling
- [ ] Breaking change

> Add the matching label: `type:bug`, `type:feature`, `type:docs`, `type:refactor`, `type:chore`, or `type:breaking-change`.

## Summary

- 1-3 bullet points of what this PR does.

## Changes

| File | Change |
|------|--------|
| `path/to/file` | What changed |

## Test Plan

- [ ] Scripts run without errors
- [ ] Manually tested the affected functionality
- [ ] Skills load correctly in target agent

## Contributor Checklist

- [ ] Linked an approved issue (`status:approved`)
- [ ] Added exactly one `type:*` label
- [ ] Shell scripts pass `shellcheck`
- [ ] Skills tested in at least one agent
- [ ] Docs updated if behavior changed
- [ ] Conventional commit format
- [ ] No `Co-Authored-By` trailers