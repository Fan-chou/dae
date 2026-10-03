#!/usr/bin/env bash
# Run owned fork test suites at the commits in dae's effective module graph.
#
# Direct and replaced module requirements pin exact fork commits. Fork tests
# live outside dae's package graph, so dae's own gate cannot exercise their
# internal ownership, protocol, and race regressions. This harness prepares
# isolated worktrees at the pinned commits and runs each fork's own tests.
#
# Usage: fork-cross-repo-test.sh [--short] [--dry-run] [--strict] [--clone-missing] [-- <args>]
#   --short          pass -short to go test (skip slow integration tests)
#   --dry-run        print what would be tested without running go test
#   --strict         exit non-zero if any fork repo test fails (default: advisory)
#   --clone-missing  clone exact pinned revisions when sibling repos are absent
#   -- <args>        everything after `--` is forwarded to `go test` verbatim
#
# Exit codes (default/advisory mode):
#   0  harness ran to completion (test failures are reported but non-fatal)
#   2  usage error / harness error (no fork found, parse failed, etc.)
# Exit codes (--strict mode):
#   0  all fork repos pass
#   1  one or more fork repos failed
#   2  usage error
#
# By default fork repos are siblings of dae. CI uses --clone-missing to fetch
# the exact revisions parsed from go.mod into an isolated temporary directory.
# Origin OQ-S6-3 (user concern): fork verification gap.
set -euo pipefail

short=0
dry_run=0
strict=0
clone_missing=0
extra_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --short) short=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --strict) strict=1; shift ;;
    --clone-missing) clone_missing=1; shift ;;
    --) shift; extra_args+=("$@"); break ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) echo "positional arg not expected: $1" >&2; exit 2 ;;
  esac
done

dae_root="$(git rev-parse --show-toplevel)"
fork_base="$(dirname "$dae_root")"
temp_root="$(mktemp -d "${TMPDIR:-/tmp}/dae-fork-test.XXXXXX")"
trap 'rm -rf "$temp_root"' EXIT

# Fork repos have their own go.mod with their own dependencies (e.g.
# golang.org/x/net) that may not be in dae's GOMODCACHE. Ensure they can be
# fetched: respect caller's GOPROXY, fall back to a CN mirror (golang.org is
# often unreachable from CN networks; same pattern as Sprint 6 L18a's
# gh-proxy workaround for github.com).
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
# Per-repo timeout in seconds (default 600s = 10min). Override via env.
per_repo_timeout="${FORK_TEST_TIMEOUT:-600}"

# Let Go resolve replacement blocks and direct/indirect requirements. Tests
# must use the selected version, not a stale textual requirement or only the
# subset of forks represented by replace directives.
parse_forks() {
  local modules logical target version commit localdir
  local outbound_seen=0 quic_seen=0 qpack_seen=0
  modules="$(go list -m -f '{{.Path}} {{with .Replace}}{{.Path}} {{.Version}}{{else}}{{.Path}} {{.Version}}{{end}}' all)" || return 1
  while read -r logical target version; do
    case "$logical" in
      github.com/daeuniverse/outbound)
        localdir=outbound
        outbound_seen=$((outbound_seen + 1))
        ;;
      github.com/olicesx/quic-go)
        localdir=quic-go
        quic_seen=$((quic_seen + 1))
        ;;
      github.com/olicesx/qpack)
        localdir=qpack
        qpack_seen=$((qpack_seen + 1))
        ;;
      *) continue ;;
    esac
    commit="${version##*-}"
    if [[ "$target" == github.com/*/* && "$commit" =~ ^[0-9a-f]{12}$ ]]; then
      printf '%s|%s|%s\n' "$localdir" "$target" "$commit"
    else
      echo "fork-cross-repo-test: unsupported owned fork version: $target $version" >&2
      return 1
    fi
  done <<< "$modules"
  if [[ "$outbound_seen" -ne 1 || "$quic_seen" -ne 1 || "$qpack_seen" -ne 1 ]]; then
    echo "fork-cross-repo-test: incomplete or duplicate fork graph (outbound=$outbound_seen quic-go=$quic_seen qpack=$qpack_seen)" >&2
    return 1
  fi
}

forks="$(parse_forks)" || exit 2
if [[ -z "$forks" ]]; then
  echo "fork-cross-repo-test: no owned pseudo-versioned forks found in the module graph" >&2
  exit 2
fi

# Build go test invocation.
test_args=(go test)
if [[ "$short" -eq 1 ]]; then
  test_args+=(-short)
fi
if [[ ${#extra_args[@]} -gt 0 ]]; then
  test_args+=("${extra_args[@]}")
fi
test_args+=(./...)

repo_count=0
failures=0
skipped=0
while IFS='|' read -r localdir target commit; do
  override_var="FORK_${localdir^^}_PATH"
  override_var="${override_var//-/_}"
  source_path="${!override_var:-$fork_base/$localdir}"
  repo_count=$((repo_count + 1))
  if ! git -C "$source_path" rev-parse --git-dir >/dev/null 2>&1; then
    if [[ "$clone_missing" -ne 1 ]]; then
      echo "SKIP: fork $localdir not found at $source_path" >&2
      skipped=$((skipped + 1))
      continue
    fi
    source_path=""
  fi
  if [[ "$dry_run" -eq 1 ]]; then
    echo "DRY-RUN: would prepare $target @ $commit and run: ${test_args[*]}"
    continue
  fi
  run_path="$temp_root/run-$localdir"
  if [[ -n "$source_path" ]]; then
    # A sibling is a read-only object source. Its origin may be another fork,
    # and tests must not leave worktree metadata or fetched refs in it.
    git clone --shared --no-checkout "$source_path" "$run_path" >/dev/null
  else
    git clone --filter=blob:none --no-checkout "https://$target.git" "$run_path" >/dev/null
  fi
  if ! git -C "$run_path" cat-file -e "${commit}^{commit}" 2>/dev/null; then
    # GitHub does not accept arbitrary abbreviated SHA wants. Fetch branch
    # history from the effective replacement repository, then resolve the pin.
    git -C "$run_path" fetch --no-tags "https://$target.git" '+refs/heads/*:refs/remotes/fork-test/*'
  fi
  git -C "$run_path" checkout --detach "$commit" >/dev/null
  echo "=== $localdir @ $commit ($run_path) ==="
  if (
    cd "$run_path"
    # QPACK's interoperability corpus is a pinned submodule, not part of
    # the module zip. Prepare it before testing the exact fork worktree.
    git submodule update --init --recursive || exit 1
    export GOWORK=off
    # Per-repo timeout prevents a hung integration test from hiding the
    # other fork's result.
    timeout "${per_repo_timeout}" "${test_args[@]}"
  ); then
    :
  else
    failures=$((failures + 1))
  fi
  rm -rf "$run_path"
done <<< "$forks"
if [[ $skipped -gt 0 ]]; then
  echo "fork-cross-repo-test: skipped $skipped/$repo_count fork repo(s)." >&2
  if [[ "$strict" -eq 1 ]]; then
    exit 2
  fi
fi

# Report paths so Producer can attach to docs/sprint-N/progress.md.
if [[ $failures -gt 0 ]]; then
  echo "fork-cross-repo-test: ${failures}/${repo_count} fork repo(s) reported test failures." >&2
  echo "  advisory mode (default): Producer reviews failures above; fork bugs are" >&2
  echo "  tracked as OQs and fixed upstream, not in dae. Use --strict to fail builds." >&2
  if [[ "$strict" -eq 1 ]]; then
    exit 1
  fi
  exit 0
fi
passed=$((repo_count - skipped))
if [[ "$dry_run" -eq 1 ]]; then
  echo "fork-cross-repo-test: dry-run planned ${passed}/${repo_count} fork repos; no tests executed."
else
  echo "fork-cross-repo-test: ${passed}/${repo_count} available fork repos pass."
fi
exit 0
