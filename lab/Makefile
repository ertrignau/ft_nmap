.DEFAULT_GOAL := help

SUDO    ?= sudo
COMPOSE ?= docker compose


help:
	@printf '%s\n' 'ft_nmap network lab'
	@printf '%s\n' ''
	@printf '%s\n' '  make up      start all 20 IPv4 targets'
	@printf '%s\n' '  make full    start target-10 only'
	@printf '%s\n' '  make ipv6    start target-10 and target-20'
	@printf '%s\n' '  make down    stop the lab'
	@printf '%s\n' '  make re      rebuild and restart everything'
	@printf '%s\n' '  make clean   remove containers/networks/volumes'
	@printf '%s\n' '  make ps      show containers'
	@printf '%s\n' '  make logs    follow logs'


up:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		up -d --build --force-recreate


full: down
	$(SUDO) $(COMPOSE) \
		--profile full \
		up -d --build --force-recreate


ipv6: down
	$(SUDO) $(COMPOSE) \
		--profile ipv6 \
		up -d --build --force-recreate


down:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		--profile ipv6 \
		down


re: down
	$(MAKE) up


clean:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		--profile ipv6 \
		down -v --remove-orphans


ps:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		--profile ipv6 \
		ps


logs:
	$(SUDO) $(COMPOSE) \
		--profile full \
		--profile fleet \
		--profile ipv6 \
		logs -f


.PHONY: \
	help \
	up \
	full \
	ipv6 \
	down \
	re \
	clean \
	ps \
	logs
