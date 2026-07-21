#!/usr/bin/env sh
#
# check-allocs.sh - surface ungated heap allocations in changed Go code and
# enforce the repository's allocation-regression tests.
#
# lneto targets bare-metal and embedded systems, so hot paths must avoid
# unbounded or ungated heap allocation: a slice grown directly from untrusted
# network data is an out-of-memory (OOM) vector (see the PR #147 review). This
# script helps catch such allocations before they land:
#
#   1. ADVISORY - runs Go escape analysis over the changed packages and lists
#      every make/append/new/closure/map in the *changed lines* that escapes to
#      the heap. These are not necessarily bugs: confirm each is bounded and
#      configurable (sized once from a user-supplied cap and reused) rather than
#      growing with untrusted input. See dhcpv6.Limits and tcp SetReassemblyBuffer
#      for the expected pattern. Advisory findings never block a commit.
#
#   2. ENFORCED - runs the allocation-regression tests (testing.AllocsPerRun,
#      named *NoAllocs / *ZeroAlloc / *no-allocs) in the changed packages. A
#      failure means a path asserted to be allocation-free has regressed; the
#      commit is blocked.
#
# Usage:
#   scripts/check-allocs.sh [file.go ...]
# With no arguments it inspects the staged Go files (git diff --cached), which
# is how the .githooks/pre-commit hook invokes it.
#
# Exit status: 0 unless an allocation-regression test fails (or tooling errors).

set -u

repo=$(git rev-parse --show-toplevel 2>/dev/null) || {
	echo "check-allocs: not inside a git repository" >&2
	exit 0
}
cd "$repo" || exit 0

tmp=$(mktemp -d) || exit 0
trap 'rm -rf "$tmp"' EXIT

# Collect target .go files: explicit args, else staged additions/modifications.
# In staged mode (no args) advisory findings are limited to the lines actually
# being added; in explicit mode every heap escape in the file is reported.
if [ "$#" -gt 0 ]; then
	staged=0
	for f in "$@"; do printf '%s\n' "$f"; done >"$tmp/files"
else
	staged=1
	git diff --cached --name-only --diff-filter=ACM -- '*.go' >"$tmp/files"
fi

# Drop deleted/absent files and vendored code.
: >"$tmp/all"
while IFS= read -r f; do
	[ -n "$f" ] || continue
	case "$f" in vendor/*) continue ;; esac
	[ -f "$f" ] && printf '%s\n' "$f" >>"$tmp/all"
done <"$tmp/files"

if [ ! -s "$tmp/all" ]; then
	exit 0
fi

# Production files (tests may allocate freely) and the set of changed packages.
grep -v '_test\.go$' "$tmp/all" >"$tmp/prod" 2>/dev/null || true
sed 's#/[^/]*$##' "$tmp/all" | sort -u | sed 's#^#./#' >"$tmp/pkgs"

if [ -t 1 ]; then
	yellow=$(printf '\033[33m'); red=$(printf '\033[31m'); green=$(printf '\033[32m'); reset=$(printf '\033[0m')
else
	yellow=; red=; green=; reset=
fi

status=0

# --- 1. Advisory: heap escapes located in changed production files. ---------
if [ -s "$tmp/prod" ]; then
	sed 's#/[^/]*$##' "$tmp/prod" | sort -u | sed 's#^#./#' >"$tmp/prodpkgs"
	: >"$tmp/esc"
	while IFS= read -r pkg; do
		# -gcflags=-m prints escape-analysis decisions on stderr as
		#   path/file.go:line:col: <expr> escapes to heap
		go build -gcflags=-m "$pkg" 2>>"$tmp/esc" >/dev/null 2>>"$tmp/esc" || true
	done <"$tmp/prodpkgs"

	# Keep only heap-allocating decisions for the changed production files.
	grep -E 'escapes to heap|moved to heap' "$tmp/esc" 2>/dev/null \
		| grep -E 'make\(|append|new\(|func literal|map\[' 2>/dev/null \
		| grep -F -f "$tmp/prod" 2>/dev/null \
		| sort -u >"$tmp/findings.all" || true

	if [ "$staged" -eq 1 ]; then
		# Restrict to lines actually being added, so pre-existing allocations in
		# a touched file are not re-reported on every commit.
		: >"$tmp/added"
		while IFS= read -r f; do
			git diff --cached -U0 -- "$f" | awk -v f="$f" '
				/^@@/ {
					plus = $3; sub(/^\+/, "", plus)
					n = split(plus, p, ","); start = p[1] + 0
					count = (n > 1) ? p[2] + 0 : 1
					for (i = 0; i < count; i++) print f ":" (start + i) ":"
				}'
		done <"$tmp/prod" >"$tmp/added"
		if [ -s "$tmp/added" ]; then
			grep -F -f "$tmp/added" "$tmp/findings.all" >"$tmp/findings" 2>/dev/null || true
		else
			: >"$tmp/findings"
		fi
	else
		cp "$tmp/findings.all" "$tmp/findings"
	fi

	if [ -s "$tmp/findings" ]; then
		printf '%s\n' "${yellow}! heap allocations in changed code - confirm each is bounded/configurable (not grown from untrusted input):${reset}"
		sed 's/^/    /' "$tmp/findings"
		printf '%s\n' "  logging/error values are expected; slices grown from network data must be capped (see dhcpv6.Limits, tcp.Handler.SetReassemblyBuffer)."
	fi
fi

# --- 2. Enforced: allocation-regression tests in changed packages. ----------
alloc_re='NoAllocs?$|noAllocs?$|ZeroAlloc|no-allocs'
while IFS= read -r pkg; do
	[ -d "${pkg#./}" ] || continue
	if go test -list "$alloc_re" "$pkg" 2>/dev/null | grep -qE "$alloc_re"; then
		if ! out=$(go test -run "$alloc_re" -count=1 "$pkg" 2>&1); then
			printf '%s\n' "${red}x allocation-regression test failed in ${pkg}:${reset}"
			printf '%s\n' "$out" | sed 's/^/    /'
			status=1
		fi
	fi
done <"$tmp/pkgs"

if [ "$status" -eq 0 ]; then
	printf '%s\n' "${green}* allocation checks passed${reset}"
fi
exit "$status"
