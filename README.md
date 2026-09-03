# Symlink Following in Indexer File-Walk → Out-of-Repo Content Disclosure via `search_text`

> **CVE status:** requested, pending assignment. This finding is published as
> [GHSA-6vhf-4wcm-2r83](https://github.com/zzet/gortex/security/advisories/GHSA-6vhf-4wcm-2r83). On CVE assignment this repository is renamed
> `CVE-YYYY-NNNNN-gortex-PoC` and this banner is replaced with the CVE link.

| | |
|---|---|
| Researcher | Dostxodjayev Abdullox ([@squeeze440](https://github.com/squeeze440)) |
| Advisory | [GHSA-6vhf-4wcm-2r83](https://github.com/zzet/gortex/security/advisories/GHSA-6vhf-4wcm-2r83) |
| CVSS 3.1 | 5.5 (Medium) |
| Weakness | CWE-59, CWE-200 |

---

# Symlink Following in Indexer File-Walk → Out-of-Repo Content Disclosure via `search_text`

## Summary
An improper link resolution flaw (CWE-59) in gortex's repository indexer allows a symlinked *file* entry pointing outside the indexed repository root to be silently walked, content-indexed, and later served verbatim — including to a fully out-of-root target — by the `search_text` MCP tool's live re-read sink, which never applies the project's own `guardSymlinkWithinRepo` confinement check.

## Product
`zzet/gortex` — https://github.com/zzet/gortex

## Tested Version
Commit `b5a63e25c0719c8ce935e59abf85618e2b4b1e64` (`git describe`: `v0.62.0-35-gb5a63e25`), the repository HEAD at audit time. Confirmed still present at the latest tagged release `v0.62.0`, i.e. after the fix for the unrelated `GHSA-w42c-h7hr-f67p` (`v0.55.0`) landed.

## Estimated CVSS v3.1
**`CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` — 5.5 (Medium)**

- `AV:L` — matches this project's own scoring precedent for its MCP surface (`GHSA-w42c-h7hr-f67p` also used `AV:L`): the default deployment is a local MCP daemon reached over stdio by the agent process on the same host; `AV:N` would only apply to the opt-in `--http-addr` mode.
- `UI:R` — requires the MCP client (an LLM agent, or a human via `gortex call`) to issue a `search_text` / `search_text regexp:true` call. A broad literal (e.g. a single common character) or a matching regex (`.`) against an indexed repo containing the planted symlink is sufficient to dump the target file — no secret knowledge of its contents needed — so this is a low bar, but it is a distinct action from mere indexing.
- `C:H` — arbitrary-file-content disclosure, unbounded by repo boundaries, of anything the daemon's OS user can read (SSH keys, cloud credential files, sibling tenants' repos in a multi-repo daemon, etc.), returned verbatim in the tool response.
- `I:N` / `A:N` — this is a pure read-path bug; nothing is written or made unavailable.

## Details

### Root cause 1 — the indexer walk never checks for symlinked file entries
`internal/indexer/indexer.go:2549-2604`, the primary corpus-admission walk:

```go
err = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
    if err != nil { return nil }
    if d.IsDir() {
        if idx.shouldPruneDir(path, absRoot) { return filepath.SkipDir }
        return nil
    }
    lang, ok := idx.effectiveLanguage(path, nil)   // detects by extension; symlink name is enough
    if !ok { return nil }
    if idx.shouldExclude(path, absRoot, false) { return nil }
    info, statErr := d.Info()                      // Lstat'd DirEntry.Info() — no ModeSymlink check
    ...
    files = append(files, walkedFile{path: path, lang: lang, size: info.Size(), mtimeNano: info.ModTime().UnixNano()})
    return nil
})
```

`filepath.WalkDir` uses `Lstat` semantics, so a symlinked *directory* is naturally protected — `d.IsDir()` is false for it and it is never recursed into. A symlinked *file* entry gets no equivalent protection: nothing here (nor in `shouldExclude`/`shouldPruneDir`, `internal/indexer/indexer.go:5724-5813`, which only match gitignore-style path patterns) calls `d.Type()&os.ModeSymlink`, `os.Lstat`, or `filepath.EvalSymlinks` on the file entry before queuing it. A file named e.g. `pwn.go` whose target is `/etc/passwd`, `~/.ssh/id_rsa`, or a sibling tenant repo is admitted purely because its *name* matches a registered extension (`effectiveLanguage`, `internal/parser` `DetectLanguageContent`, path-based). This exact walked-file list becomes `idx.fileMtimes` (`internal/indexer/indexer.go:3760`: `idx.fileMtimes[idx.relKey(f.path)] = f.mtimeNano`).

### Root cause 2 — the `search_text` sink re-reads live files with no confinement guard
`internal/indexer/grep.go:17-64` (`GrepText` / `warmTrigramSearcher`) builds the trigram searcher directly from `idx.fileMtimes`' keys:

```go
rels := ... // from idx.fileMtimes, i.e. includes the symlinked file's rel path
idx.trigramSearcher = trigram.Build(root, rels)
```

`internal/search/trigram/searcher.go:32-48` (`Build`) and `:55-86`/`:102-176` (`Grep`/`GrepRegexp`) then do:

```go
content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))  // Build — follows symlink
...
f, err := os.Open(filepath.Join(s.root, filepath.FromSlash(rel)))          // Grep/GrepRegexp — follows symlink
```

`os.ReadFile`/`os.Open` follow symlinks by default (no `O_NOFOLLOW`). Neither function, nor `internal/mcp/tools_search_text.go:35-126` (`handleSearchText`, the MCP handler that calls `s.indexer.GrepText`/`GrepRegexp`), ever calls `resolveFilePath` or `guardSymlinkWithinRepo`. Those two confinement functions exist and are correctly wired into every other content-serving path — `internal/mcp/tools_fileops.go` (`read_file`, `write_file`/`edit_file` as of the `v0.55.0` fix), `internal/mcp/tools_coding.go:919` (`get_symbol_source`), `internal/mcp/tools_lsp.go:264`, `internal/mcp/tools_export.go:95` — but `search_text`'s trigram grep path is a separate sink that was never given the same guard. `grep -rn guardSymlinkWithinRepo` across the tree confirms zero references in `tools_search_text.go`, `grep.go`, or `trigram/searcher.go`.

### Duplicate-risk / distinctness check
This is genuinely distinct from `GHSA-w42c-h7hr-f67p`:
- That advisory: **write path**, `resolveFilePath` exempting absolute paths + `write_file`/`edit_file`/`move_inline` never calling `guardSymlinkWithinRepo` (fixed in `v0.55.0`).
- This finding: **read path**, the indexer's *own discovery walk* (not any MCP handler) admits a symlinked file with no Lstat check, and a *different* MCP tool (`search_text`, not `read_file`/`get_symbol_source`) serves its content through a sink (`internal/search/trigram`) that independently never calls `guardSymlinkWithinRepo`. The write-path fix did not touch either of these two locations.
This matches the sibling-tool pattern already confirmed in `ozgurcd/gograph` (`GHSA-6h6w-vhgr-2hp6`) and `vitali87/code-graph-rag` (`GHSA-85gg-2gfq-q95m`): a file-discovery walk without symlink protection, paired with a content-serving sink that independently lacks a confinement guard.

## Proof of Concept

**Static trace** (file:line references above) is complete and reproducible by inspection. **Dynamic verification was attempted and is genuinely blocked by a toolchain gap in this sandbox**, documented honestly rather than papered over:

```
$ CGO_ENABLED=1 go test ./internal/mcp/... -run TestPoC_SymlinkFollow_SearchTextDisclosesOutOfRepoContent -v
mcp [build failed]
  cgo: C compiler "gcc" not found: exec: "gcc": executable file not found in $PATH
```

Every tree-sitter language extractor in this codebase (including the plain Go extractor, `github.com/tree-sitter/tree-sitter-go`'s `bindings/go/binding.go`: `// #cgo CFLAGS: -std=c11 -fPIC` / `import "C"`) requires cgo to compile — there is no pure-Go code path to register even a single language, so `parser.Registry` cannot be built without a working C compiler. This sandbox has no `gcc`/`cc`/`clang` on `$PATH` and no passwordless root (`sudo -l` demands an interactive password) to install one via `apt-get install gcc` (present in the apt cache, `gcc-16/kali-last-snapshot`, but unreachable without privilege). This is an environment limitation, not a finding about gortex.

The PoC test itself — written against the project's own existing test harness pattern (`internal/mcp/tools_search_text_test.go`'s `TestSearchText`, and the same `newSingleRepoServer`/`callTool` shape the prior advisory's own PoC used) — is left in place at `internal/mcp/poc_symlink_search_disclosure_test.go` for the maintainer to run in an environment with a C toolchain:

```go
func TestPoC_SymlinkFollow_SearchTextDisclosesOutOfRepoContent(t *testing.T) {
	outsideDir := t.TempDir()
	secretPath := filepath.Join(outsideDir, "secret.txt")
	const secretMarker = "GORTEX-POC-SECRET-OUTSIDE-REPO-9f3a1c"
	os.WriteFile(secretPath, []byte("BEGIN OUTSIDE-REPO FILE\n"+secretMarker+"\nEND OUTSIDE-REPO FILE\n"), 0o600)

	repoDir := t.TempDir()
	os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package app\n\nfunc Hello() {}\n"), 0o644)
	os.Symlink(secretPath, filepath.Join(repoDir, "pwn.go"))   // symlink INSIDE repo -> OUTSIDE target

	idx := indexer.New(g, reg, cfg.Index, zap.NewNop())
	idx.Index(repoDir)                                          // walk admits pwn.go, no symlink check
	srv := NewServer(eng, g, idx, nil, zap.NewNop(), nil)

	res := callTool(t, srv, "search_text", map[string]any{"query": secretMarker})
	// asserts: res.IsError == false, exactly 1 match, Path == "pwn.go",
	// Text contains secretMarker — i.e. the OUTSIDE file's real content.
}
```

Given the source-level trace above — every step named by exact function and no confinement call anywhere on the path from `filepath.WalkDir` through `trigram.Build`/`Grep` to `handleSearchText`'s response — this is presented as **statically traced, not dynamically confirmed**, per this audit's ground rule against fabricating PoC evidence.

## Impact
Any indexed repository containing a symlink whose target resolves outside that repo's root (planted by a malicious contributor, present in a cloned dependency/plugin repo, or introduced via a supply-chain PR the daemon later indexes) lets an MCP client — a normal `search_text` call, or a prompt-injected/adversarial one, same threat model as `GHSA-w42c-h7hr-f67p` — read the verbatim content of that target file, regardless of the confinement guard the project otherwise enforces on `read_file` and `get_symbol_source`. In a multi-repo daemon (`internal/indexer/multi.go:3525-3562`, which fans the identical unguarded call out per tracked repo) this also crosses tenant/repo boundaries within the same daemon instance.

## Weaknesses
- **CWE-59** — Improper Link Resolution Before File Access ('Link Following'): the indexer walk (`internal/indexer/indexer.go:2549`) admits a symlinked file entry with no `Lstat`/`ModeSymlink` check.
- **CWE-200** — Exposure of Sensitive Information to an Unauthorized Actor: `search_text` (`internal/mcp/tools_search_text.go`) → `trigram.Build`/`Grep`/`GrepRegexp` (`internal/search/trigram/searcher.go`) serve the symlink-resolved content with no `guardSymlinkWithinRepo` confinement check, unlike every other read sink in the same codebase.

## Remediation
Apply the project's own existing `guardSymlinkWithinRepo` (`internal/mcp/tools_fileops.go:353`) — or an equivalent `Lstat`-based check — at both points:
1. **Walk-time**: in the `filepath.WalkDir` callback (`internal/indexer/indexer.go:2549`), reject or skip a file `DirEntry` whose `d.Type()&os.ModeSymlink != 0` (mirroring the implicit protection `Walk` already gives directories), or resolve `filepath.EvalSymlinks(path)` and confirm containment within `absRoot` before appending to `files`.
2. **Read-time (defense in depth)**: in `trigram.Build`/`Grep`/`GrepRegexp` (`internal/search/trigram/searcher.go`), or at the `handleSearchText` call site, apply the same `guardSymlinkWithinRepo`-style real-path containment check already used by `read_file`/`get_symbol_source`/`tools_lsp`/`tools_export` before returning a match's `Text`.
Either fix alone closes this; both together match the confinement posture the rest of the codebase already holds itself to.

## Credit
Dostxodjayev Abdullox (GitHub: @squeeze440)

## Reporting Channel
Private Vulnerability Reporting (PVR) is enabled and confirmed on `zzet/gortex`; standard GitHub Security Advisory (GHSA) draft-advisory flow applies, consistent with the project's prior `GHSA-w42c-h7hr-f67p` disclosure.
