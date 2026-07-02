.DEFAULT_GOAL := help
.RECIPEPREFIX := >

# **************************************************************************** #
#                                  DOCKER LAB                                  #
# **************************************************************************** #

SUDO 	?= sudo
COMPOSE ?= docker compose
PROFILE ?= default

# **************************************************************************** #
#                                   RULES                                      #
# **************************************************************************** #

help:
> @printf '%s\n' 'ft_nmap Docker lab'
> @printf '%s\n' ''
> @printf '%s\n' 'The lab only manages the target container state.'
> @printf '%s\n' 'It does not run nmap, ft_nmap, tcpdump, strace, or tests.'
> @printf '%s\n' ''
> @printf '%s\n' 'Commands:'
> @printf '%s\n' '  make up PROFILE=default'
> @printf '%s\n' '  make up PROFILE=tcp-many-open'
> @printf '%s\n' '  make up PROFILE=udp-many-open'
> @printf '%s\n' '  make up PROFILE=mixed'
> @printf '%s\n' '  make up PROFILE=mostly-closed'
> @printf '%s\n' '  make up PROFILE=filtered-heavy'
> @printf '%s\n' ''
> @printf '%s\n' 'Aliases:'
> @printf '%s\n' '  make default'
> @printf '%s\n' '  make tcp-many-open'
> @printf '%s\n' '  make udp-many-open'
> @printf '%s\n' '  make mixed'
> @printf '%s\n' '  make mostly-closed'
> @printf '%s\n' '  make filtered-heavy'
> @printf '%s\n' ''
> @printf '%s\n' 'Other:'
> @printf '%s\n' '  make down'
> @printf '%s\n' '  make re PROFILE=<profile>'
> @printf '%s\n' '  make logs'
> @printf '%s\n' '  make shell'
> @printf '%s\n' '  make ps'
> @printf '%s\n' '  make profiles'

profiles:
> @for file in configs/*.env; do basename "$$file" .env; done

up:
> @test -f "configs/$(PROFILE).env" || { \
> 	echo "unknown lab profile: $(PROFILE)"; \
> 	echo "available profiles:"; \
> 	for file in configs/*.env; do basename "$$file" .env; done; \
> 	exit 1; \
> }
> $(SUDO) env LAB_PROFILE=$(PROFILE) $(COMPOSE) up -d --build --force-recreate

down:
> $(SUDO) $(COMPOSE) down

clean:
> $(SUDO) $(COMPOSE) down -v --remove-orphans

logs:
> $(SUDO) $(COMPOSE) logs -f target

ps:
> $(SUDO) $(COMPOSE) ps

shell:
> $(SUDO) $(COMPOSE) exec target sh

default:
> $(MAKE) up PROFILE=default

tcp-many-open:
> $(MAKE) up PROFILE=tcp-many-open

udp-many-open:
> $(MAKE) up PROFILE=udp-many-open

mixed:
> $(MAKE) up PROFILE=mixed

mostly-closed:
> $(MAKE) up PROFILE=mostly-closed

filtered-heavy:
> $(MAKE) up PROFILE=filtered-heavy

profile-%:
> $(MAKE) up PROFILE=$*

.PHONY: help profiles up down re clean logs ps shell default tcp-many-open udp-many-open mixed mostly-closed filtered-heavy
