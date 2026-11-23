#!/usr/bin/env bash
# Runs every fuzz target in the module for FUZZTIME each (default 10s).
# Go fuzzes one target per invocation, so they run in turn. A failing
# input is saved under the package's testdata/fuzz/<Target>/, where
# `go test` replays it from then on; commit it with the fix.
set -euo pipefail

fuzztime="${FUZZTIME:-10s}"
cd "$(dirname "$0")/.."

failed=()
while IFS=: read -r file line; do
	pkg="./$(dirname "$file")"
	target="$(sed -E 's/^func (Fuzz[A-Za-z0-9_]*)\(.*/\1/' <<<"$line")"
	printf '==> %s %s (%s)\n' "$pkg" "$target" "$fuzztime"
	if ! go test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime"; then
		failed+=("$pkg $target")
	fi
done < <(grep -rh --include='*_test.go' -E '^func Fuzz[A-Za-z0-9_]*\(' --with-filename . | grep -v '^./test/' | sed 's#^\./##' | sort)

if ((${#failed[@]})); then
	printf '\nFailing fuzz targets:\n' >&2
	printf '  %s\n' "${failed[@]}" >&2
	exit 1
fi
