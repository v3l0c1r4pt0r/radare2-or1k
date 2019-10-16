PLUGINS=asm anal
all: $(PLUGINS)

$(PLUGINS):
	$(MAKE) -C $@

clean:
	$(MAKE) -C asm clean
	$(MAKE) -C anal clean

install:
	$(MAKE) -C asm install
	$(MAKE) -C anal install

uninstall:
	$(MAKE) -C asm uninstall
	$(MAKE) -C anal uninstall

.PHONY: $(PLUGINS)
