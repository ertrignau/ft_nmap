#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>

/**
 * @brief Compute the Internet checksum.
 *
 * @param data Buffer to checksum.
 * @param len Buffer length in bytes.
 *
 * @return 16-bit Internet checksum ready to be written in the packet.
 */
uint16_t	nmap_checksum(const void *data, size_t len)
{
	const uint8_t	*bytes;
	uint32_t		sum;
	uint16_t		word;

	bytes = (const uint8_t *)data;
	sum = 0;
	while (len > 1)
	{
		word = ((uint16_t)bytes[0] << 8) | bytes[1];
		sum += word;
		bytes += 2;
		len -= 2;
	}
	if (len == 1)
		sum += ((uint16_t)bytes[0] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (htons((uint16_t)(~sum)));
}
