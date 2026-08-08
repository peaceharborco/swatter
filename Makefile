# Swatter — maintainer tasks. The tool itself is plain bash; this is convenience.
.PHONY: test release

# Run the full test suite. Exits non-zero if any suite fails (CI depends on this).
test:
	@fail=0; for t in test/*_test.sh; do \
		printf '%-22s ' "$$(basename $$t)"; \
		out="$$(bash "$$t")"; rc=$$?; \
		printf '%s\n' "$$out" | tail -1; \
		if [ $$rc -ne 0 ]; then \
			printf '%s\n' "$$out" | sed '$$d' | sed 's/^/    | /'; \
			fail=1; \
		fi; \
	done; exit $$fail

# Cut a release. Pass the version or a bump word, plus optional flags:
#   make release V=1.2.3
#   make release V=patch
#   make release V=minor DRY=--dry-run
release:
	@test -n "$(V)" || { echo "usage: make release V=<X.Y.Z|patch|minor|major> [DRY=--dry-run]"; exit 2; }
	@bash install/release.sh $(V) $(DRY)
