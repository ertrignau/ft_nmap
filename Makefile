# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: eric <eric@student.42.fr>                  +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2026/06/23 16:00:00 by ertrigna          #+#    #+#              #
#    Updated: 2026/06/24 16:47:29 by eric             ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME		:= ft_nmap

CC			:= gcc
CFLAGS		:= -Wall -Wextra -Werror -Iinc
LDFLAGS		:= -lpcap -pthread

SRC_DIR		:= srcs
OBJ_DIR		:= objs
INC_DIR		:= inc

SRCS		:= init.c \
			   main.c \
			   nmap.c \
			   packet.c \
			   parser.c \
			   scan_tcp.c \
			   scan_udp.c \
			   socket.c \
			   threads.c \
			   resolve.c \
			   utils.c

OBJS		:= $(addprefix $(OBJ_DIR)/, $(SRCS:.c=.o))

GREEN		:= \033[0;32m
YELLOW		:= \033[0;33m
RED			:= \033[0;31m
BLUE		:= \033[0;34m
RESET		:= \033[0m

all: $(NAME)

$(NAME): $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $(NAME)
	@printf "$(GREEN)✅ $(NAME) compiled successfully$(RESET)\n"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/nmap.h
	@mkdir -p $(OBJ_DIR)
	@printf "$(BLUE)Compiling $<...$(RESET)\n"
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJ_DIR)
	@printf "$(YELLOW)🧹 Object files removed$(RESET)\n"

fclean: clean
	@rm -f $(NAME)
	@printf "$(RED)🗑️  $(NAME) removed$(RESET)\n"

re: fclean all

debug: CFLAGS += -g3 -DDEBUG
debug: re

run: all
	@sudo ./$(NAME)

.PHONY: all clean fclean re debug run