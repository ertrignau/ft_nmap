#include "ft_nmap.h"

int	scan_name_to_mask(const char *name, uint32_t *mask)
{
	if (nmap_streq(name, "SYN"))
		*mask = NMAP_SCAN_SYN;
	else if (nmap_streq(name, "NULL"))
		*mask = NMAP_SCAN_NULL;
	else if (nmap_streq(name, "FIN"))
		*mask = NMAP_SCAN_FIN;
	else if (nmap_streq(name, "XMAS"))
		*mask = NMAP_SCAN_XMAS;
	else if (nmap_streq(name, "ACK"))
		*mask = NMAP_SCAN_ACK;
	else if (nmap_streq(name, "UDP"))
		*mask = NMAP_SCAN_UDP;
	else
		return (0);
	return (1);
}
