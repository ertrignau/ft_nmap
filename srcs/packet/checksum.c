#include "packet/packet.h"

#include <arpa/inet.h>

/**
 * @brief Add one byte buffer to a running Internet-checksum accumulator.
 *
 * @param sum Existing non-folded accumulator.
 * @param data Buffer to add.
 * @param len Buffer length in bytes.
 *
 * @return Updated non-folded accumulator.
 *
 * @note Keeping add/finalize separate lets IPv4/IPv6 pseudo headers and the
 *       transport segment be checksummed without building a temporary concat
 *       buffer.
 */
uint32_t	nmap_checksum_add(uint32_t sum, const void *data, size_t len)
{
	const uint8_t	*bytes;

	bytes = (const uint8_t *)data;
	while (len > 1)
	{
		sum += ((uint16_t)bytes[0] << 8) | bytes[1];
		bytes += 2;
		len -= 2;
	}
	if (len == 1)
		sum += ((uint16_t)bytes[0] << 8);
	return (sum);
}

/**
 * @brief Fold, one's-complement and convert a checksum accumulator to wire.
 */
uint16_t	nmap_checksum_finish(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffffU) + (sum >> 16);
	return (htons((uint16_t)(~sum)));
}

/**
 * @brief Compute a complete Internet checksum over one contiguous buffer.
 */
uint16_t	nmap_checksum(const void *data, size_t len)
{
	return (nmap_checksum_finish(nmap_checksum_add(0, data, len)));
}
