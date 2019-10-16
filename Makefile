PLUGINS=asm anal
all: $(PLUGINS)

$(PLUGINS):
	$(MAKE) -C $@

.PHONY: $(PLUGINS)
