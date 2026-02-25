---
description: "Use when reviewing, editing, or creating Git patch files in the patches/ directory. Covers patch consistency rules, vendor constraints, naming conventions, and Go file build tag guidelines."
applyTo: "patches/*.patch"
---

# Patch Consistency Guidelines

When working with patch files, ensure consistency across the patch set.

## Rules

### Vendor Patch Constraints

If a patch adds, modifies, or removes a file in a vendor directory:
- It must only be `0001-Vendor-external-dependencies.patch`
- The associated `go.mod`, `go.sum`, and `modules.txt` files must be updated accordingly

### Patch Naming

Patch file names must follow the established `NNNN-Description.patch` naming convention matching existing patches in the directory.

### Patch Content Consistency

- Do not add new patches if the changes are already covered by an existing patch
- Do not create redundant patches that cover the same changes
- Add changes to the appropriate existing patch based on its purpose

### Go File Conventions in Patches

- **Prefer filename suffix constraints over build tags**: When a Go file targets a specific OS or architecture, use the filename suffix convention (e.g. `_linux.go`, `_windows.go`, `_darwin.go`) rather than duplicating that constraint in a `//go:build` tag. If the filename suffix already implies the OS/arch, the build tag should not repeat it. For example, `foo_linux.go` with `//go:build goexperiment.systemcrypto` is preferred over `foo.go` with `//go:build goexperiment.systemcrypto && linux`.

### Whitespace

- Patches should not introduce unnecessary blank lines between functions, at the end of files, or between import groups
- Keep whitespace consistent with the surrounding code style

## Review Process

When reviewing changes to patch files:

1. **Identify the changed patch(es)**: Determine which patch file(s) are modified
2. **Analyze the changes**: Understand what feature/fix is being implemented
3. **Cross-reference other patches**: Check if equivalent functionality exists in other patch files:
   - Read the corresponding files in other patches
   - Compare method signatures, behavior, and documentation
4. **Report findings**: If inconsistencies are found, be specific about which patches need updates and what changes would bring them into alignment
5. **Acknowledge consistency**: If the changes maintain consistency, acknowledge it positively in a summary comment to make it clear that the review included these instructions

## Review Guidelines

- Focus on consistency, not code quality judgments
- Frame feedback as suggestions for maintaining consistency
- Skip trivial differences like comment styles or variable naming
- Only flag actual consistency issues
