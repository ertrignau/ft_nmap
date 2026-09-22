#include <pcap/pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

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
#define NMAP_ETHERTYPE_IPV6 0x86dd
#define NMAP_ETHERTYPE_VLAN 0x8100
#define NMAP_ETHERTYPE_QINQ 0x88a8

/** Read a network-order uint16_t without assuming packet alignment. */
static uint16_t	read_be16(const unsigned char *data)
{
	return (((uint16_t)data[0] << 8) | data[1]);
}

/** Read a little-endian uint16_t without assuming packet alignment. */
static uint16_t	read_le16(const unsigned char *data)
{
	return (((uint16_t)data[1] << 8) | data[0]);
}

/**
 * @brief Convert an Ethernet protocol value to an address family.
 */
static int	family_from_ethertype(uint16_t ethertype, sa_family_t *family)
{
	if (ethertype == NMAP_ETHERTYPE_IPV4)
		*family = AF_INET;
	else if (ethertype == NMAP_ETHERTYPE_IPV6)
		*family = AF_INET6;
	else
	{
		return (0);
	}
	return (1);
}

/**
 * @brief Validate that one candidate offset points to the expected IP version.
 */
static int	family_from_version(const unsigned char *packet,
		size_t len, size_t offset, sa_family_t *family)
{
	uint8_t	version;

	if (len <= offset)
		return (0);
	version = packet[offset] >> 4;
	if (version == 4)
		*family = AF_INET;
	else if (version == 6)
		*family = AF_INET6;
	else
	{
		return (0);
	}
	return (1);
}

/**
 * @brief Locate IPv4/IPv6 after an Ethernet header and optional VLAN tags.
 */
static int	get_ethernet_offset(const unsigned char *packet,
		size_t len, size_t *offset, sa_family_t *family)
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
	if (!family_from_ethertype(ethertype, family))
		return (0);
	*offset = pos;
	return (family_from_version(packet, len, *offset, family));
}

/** Locate IPv4/IPv6 in Linux cooked capture v1. */
static int	get_sll_offset(const unsigned char *packet,
		size_t len, size_t *offset, sa_family_t *family)
{
	if (len < NMAP_LINUX_SLL_HEADER_LEN
		|| !family_from_ethertype(read_be16(packet + 14), family))
		return (0);
	*offset = NMAP_LINUX_SLL_HEADER_LEN;
	return (family_from_version(packet, len, *offset, family));
}

/** Locate IPv4/IPv6 in Linux cooked capture v2. */
static int	get_sll2_offset(const unsigned char *packet,
		size_t len, size_t *offset, sa_family_t *family)
{
	if (len < NMAP_LINUX_SLL2_HEADER_LEN
		|| !family_from_ethertype(read_be16(packet), family))
		return (0);
	*offset = NMAP_LINUX_SLL2_HEADER_LEN;
	return (family_from_version(packet, len, *offset, family));
}

/**
 * @brief Compute the 802.11 MAC header size for a data frame.
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
 * @brief Locate IPv4/IPv6 after an 802.11 data header + LLC/SNAP.
 */
static int	get_80211_offset_at(const unsigned char *packet,
		size_t len, size_t wifi_offset, size_t *offset, sa_family_t *family)
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
	if (!family_from_ethertype(read_be16(packet + llc_offset + 6), family))
		return (0);
	*offset = llc_offset + NMAP_LLC_SNAP_LEN;
	return (family_from_version(packet, len, *offset, family));
}

/** Locate IPv4/IPv6 after a Radiotap monitor header. */
static int	get_radiotap_offset(const unsigned char *packet,
		size_t len, size_t *offset, sa_family_t *family)
{
	size_t	radiotap_len;

	if (len < NMAP_RADIOTAP_MIN_LEN || packet[0] != 0)
		return (0);
	radiotap_len = read_le16(packet + 2);
	if (radiotap_len < NMAP_RADIOTAP_MIN_LEN || radiotap_len >= len)
		return (0);
	return (get_80211_offset_at(packet, len,
			radiotap_len, offset, family));
}

/**
 * @brief Locate the network-layer header in one pcap frame.
 *
 * @param datalink Pcap DLT_* type.
 * @param packet Captured frame.
 * @param len Captured byte length.
 * @param offset Output IPv4/IPv6 offset.
 * @param family Output AF_INET or AF_INET6.
 *
 * @return 1 when a supported IPv4/IPv6 frame was located, 0 otherwise.
 *
 * @note The old code exposed nmap_get_ipv4_offset(). This function is now a
 *       true L2 boundary: it knows framing but does not parse IP protocols.
 */
int	nmap_get_network_offset(int datalink, const unsigned char *packet,
		size_t len, size_t *offset, sa_family_t *family)
{
	if (!packet || !offset || !family)
		return (0);
	if (datalink == DLT_EN10MB)
		return (get_ethernet_offset(packet, len, offset, family));
	if (datalink == DLT_LINUX_SLL)
		return (get_sll_offset(packet, len, offset, family));
#ifdef DLT_LINUX_SLL2
	if (datalink == DLT_LINUX_SLL2)
		return (get_sll2_offset(packet, len, offset, family));
#endif
	if (datalink == DLT_RAW)
	{
		*offset = 0;
		return (family_from_version(packet, len, *offset, family));
	}
#ifdef DLT_NULL
	if (datalink == DLT_NULL)
	{
		*offset = NMAP_LOOPBACK_HEADER_LEN;
		return (family_from_version(packet, len, *offset, family));
	}
#endif
#ifdef DLT_LOOP
	if (datalink == DLT_LOOP)
	{
		*offset = NMAP_LOOPBACK_HEADER_LEN;
		return (family_from_version(packet, len, *offset, family));
	}
#endif
#ifdef DLT_IEEE802_11_RADIO
	if (datalink == DLT_IEEE802_11_RADIO)
		return (get_radiotap_offset(packet, len, offset, family));
#endif
#ifdef DLT_IEEE802_11
	if (datalink == DLT_IEEE802_11)
		return (get_80211_offset_at(packet, len, 0, offset, family));
#endif
	return (0);
}
