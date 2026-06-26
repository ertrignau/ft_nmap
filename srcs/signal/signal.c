#include <signal.h>
#include <string.h>

static volatile sig_atomic_t	g_nmap_stop_requested = 0;

static void	nmap_signal_handle_sigint(int signum)
{
	(void)signum;
	g_nmap_stop_requested = 1;
}

int	nmap_signal_setup(int *exit_status)
{
	struct sigaction	action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = nmap_signal_handle_sigint;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	if (sigaction(SIGINT, &action, NULL) < 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}

int	nmap_signal_stop_requested(void)
{
	return (g_nmap_stop_requested != 0);
}