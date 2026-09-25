.DEFAULT_GOAL := all

# **************************************************************************** #
#                                  PROGRAM                                     #
# **************************************************************************** #

NAME := ft_nmap

# **************************************************************************** #
#                                  COMPILER                                    #
# **************************************************************************** #

CC := cc
CFLAGS := -Wall -Wextra -Werror
CPPFLAGS := -Iinc -Isrcs
DEPFLAGS := -MMD -MP
RM := rm -rf

# **************************************************************************** #
#                                  LIBRARIES                                   #
# **************************************************************************** #

LDLIBS := -lpcap -pthread

# **************************************************************************** #
#                                DIRECTORIES                                   #
# **************************************************************************** #

OBJS_DIR := objs
DEBUG_OBJS_DIR := objs_debug
PROFILE_OBJS_DIR := objs_profile
LAB_DIR := lab

# **************************************************************************** #
#                                  NETWORK                                     #
# **************************************************************************** #

NAT_IFACE ?= enp0s3
NAT_GW ?= 10.0.2.2
BRIDGE_IFACE ?= enp0s8
ROUTE_TEST_IP ?= 1.1.1.1

# **************************************************************************** #
#                                  SOURCES                                     #
# **************************************************************************** #

SRCS := srcs/main.c \
	srcs/run.c \
	srcs/engine/prepare.c \
	srcs/engine/loop.c \
	srcs/init/init.c \
	srcs/init/prepare_scan_config.c \
	srcs/init/targets.c \
	srcs/cleanup/cleanup.c \
	srcs/signal/signal.c \
	srcs/net/address.c \
	srcs/net/target.c \
	srcs/net/route.c \
	srcs/net/socket.c \
	srcs/net/pcap.c \
	srcs/packet/checksum.c \
	srcs/packet/ipv4.c \
	srcs/packet/ipv6.c \
	srcs/packet/send.c \
	srcs/packet/tcp.c \
	srcs/packet/udp.c \
	srcs/packet/link_offset.c \
	srcs/packet/parse.c \
	srcs/runtime/common.c \
	srcs/runtime/timing.c \
	srcs/runtime/init.c \
	srcs/runtime/match.c \
	srcs/runtime/classify.c \
	srcs/runtime/recv.c \
	srcs/runtime/expire.c \
	srcs/runtime/scheduler.c \
	srcs/runtime/worker.c \
	srcs/runtime/wait.c \
	srcs/output/report.c \
	srcs/output/verdict.c \
	srcs/output/format.c \
	srcs/output/service.c \
	srcs/output/status.c \
	srcs/parsing/pars_port.c \
	srcs/parsing/parsing_utils.c \
	srcs/parsing/pars_flags.c \
	srcs/parsing/pars_speedup.c \
	srcs/parsing/pars_scan.c \
	srcs/parsing/pars_ip.c \
	srcs/parsing/pars_timeout.c \
	srcs/parsing/pars_ttl.c \
	srcs/parsing/pars_retries.c \
	srcs/parsing/pars_file.c \
	srcs/parsing/pars_bool.c \
	srcs/parsing/parsing.c

DEBUG_SRCS := $(SRCS) srcs/debug/debug.c
PROFILE_SRCS := $(SRCS) srcs/debug/profilage.c

# **************************************************************************** #
#                                  OBJECTS                                     #
# **************************************************************************** #

OBJS := $(patsubst %.c,$(OBJS_DIR)/%.o,$(SRCS))
DEBUG_OBJS := $(patsubst %.c,$(DEBUG_OBJS_DIR)/%.o,$(DEBUG_SRCS))
PROFILE_OBJS := $(patsubst %.c,$(PROFILE_OBJS_DIR)/%.o,$(PROFILE_SRCS))

DEPS := $(OBJS:.o=.d)
DEBUG_DEPS := $(DEBUG_OBJS:.o=.d)
PROFILE_DEPS := $(PROFILE_OBJS:.o=.d)

# **************************************************************************** #
#                                   RULES                                      #
# **************************************************************************** #

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDLIBS) -o $(NAME)

debug: $(DEBUG_OBJS)
	$(CC) $(CFLAGS) -DDEBUG $(DEBUG_OBJS) $(LDLIBS) -o $(NAME)

profile: $(PROFILE_OBJS)
	$(CC) $(CFLAGS) -DPROFILE $(PROFILE_OBJS) $(LDLIBS) -o $(NAME)

$(OBJS_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEPFLAGS) -c $< -o $@

$(DEBUG_OBJS_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DDEBUG $(CPPFLAGS) $(DEPFLAGS) -c $< -o $@

$(PROFILE_OBJS_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DPROFILE $(CPPFLAGS) $(DEPFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJS_DIR) $(DEBUG_OBJS_DIR) $(PROFILE_OBJS_DIR)

fclean: clean
	$(RM) $(NAME)

re: fclean all

run: all
	sudo ./$(NAME)

debug-run: debug
	sudo ./$(NAME)

profile-run: profile
	sudo ./$(NAME)

# **************************************************************************** #
#                                    TESTS                                     #
# **************************************************************************** #

test: all
	@python3 tools/test_runner.py

# **************************************************************************** #
#                                  NETWORK                                     #
# **************************************************************************** #

net-check:
	@printf "\nInterfaces:\n"
	@ip -br addr
	@printf "\nRouting table:\n"
	@ip route
	@printf "\nInternet route ($(ROUTE_TEST_IP)):\n"
	@ip route get $(ROUTE_TEST_IP) || true
	@printf "\nNAT / SSH route ($(NAT_GW)):\n"
	@ip route get $(NAT_GW) || true

net-bridge:
	@printf "Activating bridge interface: $(BRIDGE_IFACE)\n"
	@sudo ip link set $(BRIDGE_IFACE) up
	@sudo dhclient -r $(BRIDGE_IFACE) >/dev/null 2>&1 || true
	@sudo dhclient -v $(BRIDGE_IFACE)
	@GW=$$(ip route show default dev $(BRIDGE_IFACE) \
		| awk 'NR == 1 {print $$3}'); \
	if [ -z "$$GW" ]; then \
		printf "Error: no gateway found for $(BRIDGE_IFACE)\n" >&2; \
		exit 1; \
	fi; \
	printf "Bridge gateway: %s\n" "$$GW"; \
	sudo ip route flush default dev $(NAT_IFACE); \
	sudo ip route flush default dev $(BRIDGE_IFACE); \
	sudo ip route add default via "$$GW" dev $(BRIDGE_IFACE)
	@printf "\nInternet route:\n"
	@ip route get $(ROUTE_TEST_IP)
	@printf "\nSSH route:\n"
	@ip route get $(NAT_GW)

net-nat:
	@printf "Restoring NAT as default route\n"
	@sudo ip route flush default dev $(BRIDGE_IFACE)
	@sudo ip route flush default dev $(NAT_IFACE)
	@sudo ip route add default via $(NAT_GW) dev $(NAT_IFACE)
	@printf "\nInternet route:\n"
	@ip route get $(ROUTE_TEST_IP)
	@printf "\nSSH route:\n"
	@ip route get $(NAT_GW)

# **************************************************************************** #
#                                  DOCKER LAB                                  #
# **************************************************************************** #

lab: lab-up

lab-up:
	$(MAKE) -C $(LAB_DIR) up

lab-full:
	$(MAKE) -C $(LAB_DIR) full

lab-ipv6:
	$(MAKE) -C $(LAB_DIR) ipv6

lab-down:
	$(MAKE) -C $(LAB_DIR) down

lab-re:
	$(MAKE) -C $(LAB_DIR) re

lab-clean:
	$(MAKE) -C $(LAB_DIR) clean

lab-ps:
	$(MAKE) -C $(LAB_DIR) ps

lab-logs:
	$(MAKE) -C $(LAB_DIR) logs

# **************************************************************************** #
#                                DEPENDENCIES                                  #
# **************************************************************************** #

-include $(DEPS)
-include $(DEBUG_DEPS)
-include $(PROFILE_DEPS)

.PHONY: all debug profile clean fclean re \
	run debug-run profile-run test \
	net-check net-bridge net-nat \
	lab lab-up lab-full lab-ipv6 lab-down lab-re lab-clean lab-ps lab-logs