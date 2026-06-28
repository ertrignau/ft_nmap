#include <stddef.h>
#include <stdint.h>
#include <pcap/pcap.h>

#define NMAP_ETHERNET_HEADER_LEN 14
#define NMAP_LINUX_SLL_HEADER_LEN 16
#define NMAP_LINUX_SLL2_HEADER_LEN 20
#define NMAP_LOOPBACK_HEADER_LEN 4
#define NMAP_RADIOTAP_MIN_LEN 8
#define NMAP_80211_BASE_HEADER_LEN 24
#define NMAP_80211_ADDR4_LEN 6
#define NMAP_80211_QOS_LEN 2
#define NMAP_80211_HT_CONTROL_LEN 4
#define NMAP_LLC_SNAP_LEN 8
#define NMAP_ETHERTYPE_IPV4 0x0800
#define NMAP_ETHERTYPE_VLAN 0x8100
#define NMAP_ETHERTYPE_QINQ 0x88a8

/**
 * @brief Read a big-endian uint16_t from a packet buffer.
 *
 * @param data Pointer to the 2-byte field.
 *
 * @return Host-order uint16_t value.
 */
static uint16_t	read_be16(const unsigned char *data)
{
	return (((uint16_t)data[0] << 8) | data[1]);
}

/**
 * @brief Read a little-endian uint16_t from a packet buffer.
 *
 * @param data Pointer to the 2-byte field.
 *
 * @return Host-order uint16_t value.
 */
static uint16_t	read_le16(const unsigned char *data)
{
	return (((uint16_t)data[1] << 8) | data[0]);
}

/**
 * @brief Check whether a packet byte looks like an IPv4 header start.
 *
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param offset Candidate IPv4 offset.
 *
 * @return 1 if the offset points to an IPv4 header, 0 otherwise.
 */
static int	offset_points_to_ipv4(const unsigned char *packet,
		size_t len, size_t offset)
{
	if (len < offset + 1)
		return (0);
	return ((packet[offset] >> 4) == 4);
}

/**
 * @brief Return IPv4 offset for Ethernet-like packets.
 *
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param offset Output IPv4 offset.
 *
 * @return 1 on IPv4 packet, 0 otherwise.
 *
 * @note Supports normal Ethernet and one or more VLAN tags.
 */
static int	get_ethernet_ipv4_offset(const unsigned char *packet,
		size_t len, size_t *offset)
{
	size_t		pos;
	uint16_t	ethertype;

	if (len < NMAP_ETHERNET_HEADER_LEN)
		return (0);
	pos = 12;
	ethertype = read_be16(packet + pos);
	pos += 2;
	while (ethertype == NMAP_ETHERTYPE_VLAN
		|| ethertype == NMAP_ETHERTYPE_QINQ)
	{
		if (len < pos + 4)
			return (0);
		ethertype = read_be16(packet + pos + 2);
		pos += 4;
	}
	if (ethertype != NMAP_ETHERTYPE_IPV4)
		return (0);
	*offset = pos;
	return (offset_points_to_ipv4(packet, len, *offset));
}

/**
 * @brief Return IPv4 offset for Linux cooked capture v1.
 *
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param offset Output IPv4 offset.
 *
 * @return 1 on IPv4 packet, 0 otherwise.
 */
static int	get_linux_sll_ipv4_offset(const unsigned char *packet,
		size_t len, size_t *offset)
{
	if (len < NMAP_LINUX_SLL_HEADER_LEN)
		return (0);
	if (read_be16(packet + 14) != NMAP_ETHERTYPE_IPV4)
		return (0);
	*offset = NMAP_LINUX_SLL_HEADER_LEN;
	return (offset_points_to_ipv4(packet, len, *offset));
}

/**
 * @brief Return IPv4 offset for Linux cooked capture v2.
 *
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param offset Output IPv4 offset.
 *
 * @return 1 on IPv4 packet, 0 otherwise.
 */
static int	get_linux_sll2_ipv4_offset(const unsigned char *packet,
		size_t len, size_t *offset)
{
	if (len < NMAP_LINUX_SLL2_HEADER_LEN)
		return (0);
	if (read_be16(packet) != NMAP_ETHERTYPE_IPV4)
		return (0);
	*offset = NMAP_LINUX_SLL2_HEADER_LEN;
	return (offset_points_to_ipv4(packet, len, *offset));
}

/**
 * @brief Return IPv4 offset for raw IP packets.
 *
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param offset Output IPv4 offset.
 *
 * @return 1 on IPv4 packet, 0 otherwise.
 */
static int	get_raw_ipv4_offset(const unsigned char *packet,
		size_t len, size_t *offset)
{
	*offset = 0;
	return (offset_points_to_ipv4(packet, len, *offset));
}

/**
 * @brief Return IPv4 offset for loopback captures.
 *
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param offset Output IPv4 offset.
 *
 * @return 1 on IPv4 packet, 0 otherwise.
 */
static int	get_loopback_ipv4_offset(const unsigned char *packet,
		size_t len, size_t *offset)
{
	if (len < NMAP_LOOPBACK_HEADER_LEN)
		return (0);
	*offset = NMAP_LOOPBACK_HEADER_LEN;
	return (offset_points_to_ipv4(packet, len, *offset));
}

/**
 * @brief Compute the 802.11 MAC header length.
 *
 * @param frame_control 802.11 frame control field in host order.
 *
 * @return Header length in bytes, or 0 if the frame is not a data frame.
 */
static size_t	get_80211_header_len(uint16_t frame_control)
{
	size_t	header_len;
	uint8_t	type;
	uint8_t	subtype;
	int		to_ds;
	int		from_ds;
	int		qos;
	int		order;

	type = (frame_control >> 2) & 0x3;
	subtype = (frame_control >> 4) & 0xf;
	to_ds = (frame_control & 0x0100) != 0;
	from_ds = (frame_control & 0x0200) != 0;
	order = (frame_control & 0x8000) != 0;
	if (type != 2)
		return (0);
	header_len = NMAP_80211_BASE_HEADER_LEN;
	if (to_ds && from_ds)
		header_len += NMAP_80211_ADDR4_LEN;
	qos = (subtype & 0x08) != 0;
	if (qos)
		header_len += NMAP_80211_QOS_LEN;
	if (order)
		header_len += NMAP_80211_HT_CONTROL_LEN;
	return (header_len);
}

/**
 * @brief Return IPv4 offset after an 802.11 header and LLC/SNAP.
 *
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param wifi_offset Offset of the 802.11 frame.
 * @param offset Output IPv4 offset.
 *
 * @return 1 on IPv4 packet, 0 otherwise.
 */
static int	get_80211_ipv4_offset_at(const unsigned char *packet,
		size_t len, size_t wifi_offset, size_t *offset)
{
	uint16_t	frame_control;
	size_t		wifi_header_len;
	size_t		llc_offset;

	if (len < wifi_offset + 2)
		return (0);
	frame_control = read_le16(packet + wifi_offset);
	if (frame_control & 0x4000)
		return (0);
	wifi_header_len = get_80211_header_len(frame_control);
	if (wifi_header_len == 0)
		return (0);
	llc_offset = wifi_offset + wifi_header_len;
	if (len < llc_offset + NMAP_LLC_SNAP_LEN)
		return (0);
	if (packet[llc_offset] != 0xaa || packet[llc_offset + 1] != 0xaa
		|| packet[llc_offset + 2] != 0x03)
		return (0);
	if (read_be16(packet + llc_offset + 6) != NMAP_ETHERTYPE_IPV4)
		return (0);
	*offset = llc_offset + NMAP_LLC_SNAP_LEN;
	return (offset_points_to_ipv4(packet, len, *offset));
}

/**
 * @brief Return IPv4 offset for Radiotap + 802.11 monitor captures.
 *
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param offset Output IPv4 offset.
 *
 * @return 1 on IPv4 packet, 0 otherwise.
 */
static int	get_radiotap_ipv4_offset(const unsigned char *packet,
		size_t len, size_t *offset)
{
	size_t	radiotap_len;

	if (len < NMAP_RADIOTAP_MIN_LEN)
		return (0);
	if (packet[0] != 0)
		return (0);
	radiotap_len = read_le16(packet + 2);
	if (radiotap_len < NMAP_RADIOTAP_MIN_LEN || radiotap_len >= len)
		return (0);
	return (get_80211_ipv4_offset_at(packet, len, radiotap_len, offset));
}

/**
 * @brief Return the offset of the IPv4 header in a pcap packet.
 *
 * @param datalink Pcap datalink type.
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param offset Output IPv4 offset.
 *
 * @return 1 when IPv4 offset was found, 0 otherwise.
 *
 * @note Layer 2 headers are only used to locate IPv4. Their addresses and
 *       metadata are not used for scan matching or classification.
 */
int	nmap_get_ipv4_offset(int datalink, const unsigned char *packet,
		size_t len, size_t *offset)
{
	if (!packet || !offset)
		return (0);
	if (datalink == DLT_EN10MB)
		return (get_ethernet_ipv4_offset(packet, len, offset));
	if (datalink == DLT_LINUX_SLL)
		return (get_linux_sll_ipv4_offset(packet, len, offset));
#ifdef DLT_LINUX_SLL2
	if (datalink == DLT_LINUX_SLL2)
		return (get_linux_sll2_ipv4_offset(packet, len, offset));
#endif
	if (datalink == DLT_RAW)
		return (get_raw_ipv4_offset(packet, len, offset));
#ifdef DLT_NULL
	if (datalink == DLT_NULL)
		return (get_loopback_ipv4_offset(packet, len, offset));
#endif
#ifdef DLT_LOOP
	if (datalink == DLT_LOOP)
		return (get_loopback_ipv4_offset(packet, len, offset));
#endif
#ifdef DLT_IEEE802_11_RADIO
	if (datalink == DLT_IEEE802_11_RADIO)
		return (get_radiotap_ipv4_offset(packet, len, offset));
#endif
#ifdef DLT_IEEE802_11
	if (datalink == DLT_IEEE802_11)
		return (get_80211_ipv4_offset_at(packet, len, 0, offset));
#endif
	return (0);
}