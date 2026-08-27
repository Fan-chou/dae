# Durable Go caches for local make/test.
#
# Cursor/agent sandboxes rewrite GOCACHE to a per-session /tmp tree, which
# forces a cold compile (and often a module refetch) on every run. Re-pin
# unless the caller sets KDAE_KEEP_SANDBOX_CACHE=1.
#
# Preference: existing machine cache ($HOME/go-cache or ~/.cache/go-build).
# If that path is not writable, fall back to ./.gocache (gitignored) so
# consecutive runs in this workspace still share objects.

ifeq ($(KDAE_KEEP_SANDBOX_CACHE),1)
else
  _kdae_gocache_ephemeral :=
  ifneq ($(findstring cursor-sandbox-cache,$(GOCACHE)),)
    _kdae_gocache_ephemeral := 1
  endif
  ifneq ($(GOCACHE),)
    ifeq ($(GOCACHE),$(filter /tmp/%,$(GOCACHE)))
      _kdae_gocache_ephemeral := 1
    endif
  endif
  ifeq ($(_kdae_gocache_ephemeral),1)
    ifneq ($(wildcard $(HOME)/go-cache/.),)
      export GOCACHE := $(HOME)/go-cache
    else
      export GOCACHE := $(HOME)/.cache/go-build
    endif
    _kdae_gocache_writable := $(shell mkdir -p "$(GOCACHE)" >/dev/null 2>&1 && touch "$(GOCACHE)/.kdae-write" >/dev/null 2>&1 && rm -f "$(GOCACHE)/.kdae-write" && echo ok)
    ifneq ($(_kdae_gocache_writable),ok)
      export GOCACHE := $(CURDIR)/.gocache
    endif
  endif
endif

ifneq ($(GOCACHE),)
  $(shell mkdir -p "$(GOCACHE)")
endif
