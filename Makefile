# Swatter — maintainer tasks. The tool itself is plain bash; this is convenience.
.PHONY: test release

# Run the full test suite.
test:
	@for t in test/*_test.sh; do printf '%-22s ' "$$(basename $$t)"; bash "$$t" | tail -1; done

# Cut a release. Pass the version or a bump word, plus optional flags:
#   make release V=1.2.3
#   make release V=patch
#   make release V=minor DRY=--dry-run
release:
	@test -n "$(V)" || { echo "usage: make release V=<X.Y.Z|patch|minor|major> [DRY=--dry-run]"; exit 2; }
	@bash install/release.sh $(V) $(DRY)
