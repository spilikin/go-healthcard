VERSION := 0.1.0

.PHONY: info, release

info:
	@echo "Version: $(VERSION)"
	@echo "Usage:"
	@echo "  make release"

release:
	@echo "Release version $(VERSION)"
	gh release create $(VERSION) -t $(VERSION) -n "Release $(VERSION)" 

