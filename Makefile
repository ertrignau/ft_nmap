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

# **************************************************************************** #
#                                  SOURCES                                     #
# **************************************************************************** #

SRCS :=	srcs/main.c \
		srcs/dev_config.c \
		srcs/cleanup/cleanup.c \
		srcs/signal/signal.c \
		srcs/net/socket.c \
		srcs/net/pcap.c \
		srcs/packet/tcp.c \
		srcs/packet/udp.c \
		srcs/packet/checksum.c \
		srcs/runtime/init.c \
		srcs/runtime/scheduler.c \
		srcs/runtime/worker.c \
		srcs/runtime/recv.c \
		srcs/runtime/expire.c \
		srcs/runtime/wait.c \
		srcs/runtime/classify.c \
		srcs/output/report.c \
		srcs/packet/parse.c \
		srcs/packet/link_offset.c

DEBUG_SRCS :=	$(SRCS) \
				srcs/debug/debug.c

PROFILE_SRCS :=	$(SRCS) \
				srcs/debug/profilage.c

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
	$(RM) $(OBJS_DIR)
	$(RM) $(DEBUG_OBJS_DIR)
	$(RM) $(PROFILE_OBJS_DIR)

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
#                                DEPENDENCIES                                  #
# **************************************************************************** #

-include $(DEPS)
-include $(DEBUG_DEPS)
-include $(PROFILE_DEPS)

.PHONY: all debug profile clean fclean re run debug-run profile-run