package wifi

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// errInvalidIE is returned when one or more IEs are malformed.
var errInvalidIE = errors.New("invalid 802.11 information element")

// errInvalidBSSLoad is returned when BSSLoad IE has wrong length.
var errInvalidBSSLoad = errors.New("802.11 information element BSSLoad has wrong length")

// RSN (Robust Security Network) Information Element parsing errors
var (
	// Base error for all RSN parsing errors
	errRSNParse = errors.New("RSN IE parsing error")

	// Specific RSN parsing errors that wrap the base error
	errRSNDataTooLarge                = fmt.Errorf("%w: data exceeds maximum size of 253 octets", errRSNParse)
	errRSNTooShort                    = fmt.Errorf("%w: IE too short", errRSNParse)
	errRSNInvalidVersion              = fmt.Errorf("%w: invalid version 0", errRSNParse)
	errRSNTruncatedPairwiseCount      = fmt.Errorf("%w: truncated before pairwise count", errRSNParse)
	errRSNPairwiseCipherCountTooLarge = fmt.Errorf("%w: pairwise cipher count too large", errRSNParse)
	errRSNTruncatedPairwiseList       = fmt.Errorf("%w: truncated in pairwise list", errRSNParse)
	errRSNAKMCountTooLarge            = fmt.Errorf("%w: AKM count too large", errRSNParse)
	errRSNTruncatedAKMList            = fmt.Errorf("%w: truncated in AKM list", errRSNParse)
	errRSNTooSmallForCounts           = fmt.Errorf("%w: too small for declared cipher/AKM counts", errRSNParse)
	errRSNPMKIDCountTooLarge          = fmt.Errorf("%w: PMKID count too large", errRSNParse)
	errRSNTruncatedPMKIDList          = fmt.Errorf("%w: truncated in PMKID list", errRSNParse)
)

// An InterfaceType is the operating mode of an Interface.
type InterfaceType int

const (
	// InterfaceTypeUnspecified indicates that an interface's type is unspecified
	// and the driver determines its function.
	InterfaceTypeUnspecified InterfaceType = iota

	// InterfaceTypeAdHoc indicates that an interface is part of an independent
	// basic service set (BSS) of client devices without a controlling access
	// point.
	InterfaceTypeAdHoc

	// InterfaceTypeStation indicates that an interface is part of a managed
	// basic service set (BSS) of client devices with a controlling access point.
	InterfaceTypeStation

	// InterfaceTypeAP indicates that an interface is an access point.
	InterfaceTypeAP

	// InterfaceTypeAPVLAN indicates that an interface is a VLAN interface
	// associated with an access point.
	InterfaceTypeAPVLAN

	// InterfaceTypeWDS indicates that an interface is a wireless distribution
	// interface, used as part of a network of multiple access points.
	InterfaceTypeWDS

	// InterfaceTypeMonitor indicates that an interface is a monitor interface,
	// receiving all frames from all clients in a given network.
	InterfaceTypeMonitor

	// InterfaceTypeMeshPoint indicates that an interface is part of a wireless
	// mesh network.
	InterfaceTypeMeshPoint

	// InterfaceTypeP2PClient indicates that an interface is a client within
	// a peer-to-peer network.
	InterfaceTypeP2PClient

	// InterfaceTypeP2PGroupOwner indicates that an interface is the group
	// owner within a peer-to-peer network.
	InterfaceTypeP2PGroupOwner

	// InterfaceTypeP2PDevice indicates that an interface is a device within
	// a peer-to-peer client network.
	InterfaceTypeP2PDevice

	// InterfaceTypeOCB indicates that an interface is outside the context
	// of a basic service set (BSS).
	InterfaceTypeOCB

	// InterfaceTypeNAN indicates that an interface is part of a near-me
	// area network (NAN).
	InterfaceTypeNAN
)

// String returns the string representation of an InterfaceType.
func (t InterfaceType) String() string {
	switch t {
	case InterfaceTypeUnspecified:
		return "unspecified"
	case InterfaceTypeAdHoc:
		return "ad-hoc"
	case InterfaceTypeStation:
		return "station"
	case InterfaceTypeAP:
		return "access point"
	case InterfaceTypeAPVLAN:
		return "access point/VLAN"
	case InterfaceTypeWDS:
		return "wireless distribution"
	case InterfaceTypeMonitor:
		return "monitor"
	case InterfaceTypeMeshPoint:
		return "mesh point"
	case InterfaceTypeP2PClient:
		return "P2P client"
	case InterfaceTypeP2PGroupOwner:
		return "P2P group owner"
	case InterfaceTypeP2PDevice:
		return "P2P device"
	case InterfaceTypeOCB:
		return "outside context of BSS"
	case InterfaceTypeNAN:
		return "near-me area network"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// A ChannelWidth is the width of a WiFi channel.
//
// On Linux, ChannelWidth copies the ordering of nl80211's channel width constants.
// This may not be the case on other operating systems.
// See: https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/nl80211.h#L5136-L5177
type ChannelWidth int

const (
	ChannelWidth20NoHT ChannelWidth = iota
	ChannelWidth20
	ChannelWidth40
	ChannelWidth80
	ChannelWidth80P80
	ChannelWidth160
	ChannelWidth5
	ChannelWidth10
	ChannelWidth1
	ChannelWidth2
	ChannelWidth4
	ChannelWidth8
	ChannelWidth16
	ChannelWidth320
)

// String returns the string representation of an InterfaceType.
func (t ChannelWidth) String() string {
	switch t {
	case ChannelWidth20NoHT:
		return "20 MHz (no HT)"
	case ChannelWidth20:
		return "20 MHz"
	case ChannelWidth40:
		return "40 MHz"
	case ChannelWidth80:
		return "80 MHz"
	case ChannelWidth80P80:
		return "80+80 MHz"
	case ChannelWidth160:
		return "160 MHz"
	case ChannelWidth5:
		return "5 MHz"
	case ChannelWidth10:
		return "10 MHz"
	case ChannelWidth1:
		return "1 MHz"
	case ChannelWidth2:
		return "2 MHz"
	case ChannelWidth4:
		return "4 MHz"
	case ChannelWidth8:
		return "8 MHz"
	case ChannelWidth16:
		return "16 MHz"
	case ChannelWidth320:
		return "320 MHz"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// An Interface is a WiFi network interface.
type Interface struct {
	// The index of the interface.
	Index int

	// The name of the interface.
	Name string

	// The hardware address of the interface.
	HardwareAddr net.HardwareAddr

	// The physical device that this interface belongs to.
	PHY int

	// The virtual device number of this interface within a PHY.
	Device int

	// The operating mode of the interface.
	Type InterfaceType

	// The interface's wireless frequency in MHz.
	Frequency int

	// The interface's wireless channel width.
	ChannelWidth ChannelWidth
}

// RateModulationInfo is implemented by modulation types in this package.
// External implementations are not supported.
type RateModulationInfo interface {
	// MCS is the modulation and coding scheme index.
	GetMCS() int

	// NSS is the number of spatial streams.
	GetNSS() int

	// String returns a human-readable description of the modulation info.
	// Format is more verbose and includes all relevant information.
	String() string

	// WifiGeneration returns the WiFi generation (e.g., "802.11n (WiFi 4)", "802.11ac (WiFi 5)", "802.11ax (WiFi 6)", "802.11be (WiFi 7)")
	WifiGeneration() string

	// HasShortGI reports whether this modulation currently uses short guard interval.
	HasShortGI() bool

	// formatRateInfoWithWidth renders modulation details for RateInfo.String's
	// iw-style output. It is unexported to prevent external implementations.
	formatRateInfoWithWidth(channelWidth string) string
}

type BaseModulationInfo struct {
	MCS int
	NSS int
}

func (mi BaseModulationInfo) GetMCS() int {
	return mi.MCS
}

func (mi BaseModulationInfo) GetNSS() int {
	return mi.NSS
}

func (mi BaseModulationInfo) WifiGeneration() string {
	return "unknown"
}

func (mi BaseModulationInfo) HasShortGI() bool {
	return false
}

func (mi BaseModulationInfo) String() string {
	return fmt.Sprintf("MCS: %d, NSS: %d", mi.MCS, mi.NSS)
}

func (mi BaseModulationInfo) formatRateInfoWithWidth(channelWidth string) string {
	parts := []string{fmt.Sprintf("MCS %d", mi.MCS), fmt.Sprintf("NSS %d", mi.NSS)}
	if channelWidth == "" {
		return strings.Join(parts, " ")
	}

	parts = append(parts, channelWidth)
	return strings.Join(parts, " ")
}

// HTModulationInfo represents modulation information for HT rates.
// MCS Indexes originally range from 0 to 31. NSS is coded in the MCS index as follows:
// NSS = (MCS / 8) + 1
// MCS = MCS % 8
// original MCS index is available as HTMCS
type HTModulationInfo struct {
	BaseModulationInfo
	HTMCS   int
	ShortGI bool
}

func (mi HTModulationInfo) WifiGeneration() string {
	return "802.11n (WiFi 4)"
}

func (mi HTModulationInfo) HasShortGI() bool {
	return mi.ShortGI
}

func (mi HTModulationInfo) String() string {
	return fmt.Sprintf("HT-MCS: %d, MCS: %d, NSS: %d, Short GI: %t", mi.HTMCS, mi.MCS, mi.NSS, mi.ShortGI)
}

func (mi HTModulationInfo) formatRateInfoWithWidth(channelWidth string) string {
	parts := []string{fmt.Sprintf("MCS %d", mi.HTMCS)}
	if channelWidth != "" {
		parts = append(parts, channelWidth)
	}
	if channelWidth != "" && mi.HasShortGI() {
		parts = append(parts, "short GI")
	}

	return strings.Join(parts, " ")
}

// VHTModulationInfo represents modulation information for VHT rates.
type VHTModulationInfo struct {
	BaseModulationInfo
	ShortGI bool
}

func (mi VHTModulationInfo) WifiGeneration() string {
	return "802.11ac (WiFi 5)"
}

func (mi VHTModulationInfo) HasShortGI() bool {
	return mi.ShortGI
}

func (mi VHTModulationInfo) String() string {
	return fmt.Sprintf("VHT-MCS: %d, NSS: %d, Short GI: %t", mi.MCS, mi.NSS, mi.ShortGI)
}

func (mi VHTModulationInfo) formatRateInfoWithWidth(channelWidth string) string {
	parts := []string{fmt.Sprintf("VHT-MCS %d", mi.MCS)}
	if channelWidth != "" {
		parts = append(parts, channelWidth)
	}
	if channelWidth != "" && mi.HasShortGI() {
		parts = append(parts, "short GI")
	}
	parts = append(parts, fmt.Sprintf("VHT-NSS %d", mi.NSS))

	return strings.Join(parts, " ")
}

type HEModulationInfo struct {
	BaseModulationInfo
	GI      int
	DCM     int
	RUAlloc int
}

func (mi HEModulationInfo) WifiGeneration() string {
	return "802.11ax (WiFi 6)"
}

func (mi HEModulationInfo) String() string {
	return fmt.Sprintf("HE-MCS: %d, NSS: %d, GI: %d, DCM: %d, RUAlloc: %d", mi.MCS, mi.NSS, mi.GI, mi.DCM, mi.RUAlloc)
}

func (mi HEModulationInfo) formatRateInfoWithWidth(channelWidth string) string {
	parts := []string{}
	if channelWidth != "" {
		parts = append(parts, channelWidth)
	}

	parts = append(parts,
		fmt.Sprintf("HE-MCS %d", mi.MCS),
		fmt.Sprintf("HE-NSS %d", mi.NSS),
		fmt.Sprintf("HE-GI %d", mi.GI),
		fmt.Sprintf("HE-DCM %d", mi.DCM),
		fmt.Sprintf("HE-RU-ALLOC %d", mi.RUAlloc),
	)

	return strings.Join(parts, " ")
}

type EHTModulationInfo struct {
	BaseModulationInfo
	GI      int
	RUAlloc int
}

func (mi EHTModulationInfo) WifiGeneration() string {
	return "802.11be (WiFi 7)"
}

func (mi EHTModulationInfo) String() string {
	return fmt.Sprintf("EHT-MCS: %d, NSS: %d, GI: %d, RUAlloc: %d", mi.MCS, mi.NSS, mi.GI, mi.RUAlloc)
}

func (mi EHTModulationInfo) formatRateInfoWithWidth(channelWidth string) string {
	parts := []string{}
	if channelWidth != "" {
		parts = append(parts, channelWidth)
	}

	parts = append(parts,
		fmt.Sprintf("EHT-MCS %d", mi.MCS),
		fmt.Sprintf("EHT-NSS %d", mi.NSS),
		fmt.Sprintf("EHT-GI %d", mi.GI),
		fmt.Sprintf("EHT-RU-ALLOC %d", mi.RUAlloc),
	)

	return strings.Join(parts, " ")
}

// RateModulationInfoType indicates the type of modulation used for a rate.
type RateModulationInfoType int

const (
	RateModulationInfoTypeHT RateModulationInfoType = iota
	RateModulationInfoTypeVHT
	RateModulationInfoTypeHE
	RateModulationInfoTypeEHT
	RateModulationInfoTypeLegacy
	RateModulationInfoTypeUNKNOWN
)

// rateInfo provides information about the receive or transmit rate of
// an interface.
type RateInfo struct {
	// Bitrate in 100 kbit/s units (nl80211 rate_info convention).
	// For example, 867 means 86.7 MBit/s.
	Bitrate int

	// The type of modulation used. Can also be inferred from Modulation.(type)
	ModulationType RateModulationInfoType

	// Modulation information.
	Modulation RateModulationInfo

	// Channel width used for this rate.
	ChannelWidth ChannelWidth
}

func bitrateStr(bitrate int) string {
	if bitrate > 0 {
		return fmt.Sprintf("%d.%d MBit/s", bitrate/10, bitrate%10)
	}
	return "(unknown)"
}

func iwChannelWidthString(w ChannelWidth) string {
	return strings.ReplaceAll(strings.ReplaceAll(w.String(), " ", ""), "+", "P")
}

// String returns the bitrate and modulation details formatted similarly to
// iw's parse_bitrate output, including iw-style token ordering.
func (r RateInfo) String() string {
	// Keep output intentionally close to iw's parse_bitrate token order.
	// This looks unusual in places (for example VHT-NSS appearing after width
	// and optional short GI), but it matches iw-style formatting.
	parts := []string{bitrateStr(r.Bitrate)}
	width := iwChannelWidthString(r.ChannelWidth)

	// No modulation details: print bitrate plus channel width only.
	if r.Modulation == nil {
		parts = append(parts, width)
		return strings.Join(parts, " ")
	}

	if formatted := r.Modulation.formatRateInfoWithWidth(width); formatted != "" {
		parts = append(parts, formatted)
	}

	return strings.Join(parts, " ")
}

// StationInfo contains statistics about a WiFi interface operating in
// station mode.
type StationInfo struct {
	// The interface that this station is associated with.
	InterfaceIndex int

	// The hardware address of the station.
	HardwareAddr net.HardwareAddr

	// The time since the station last connected.
	Connected time.Duration

	// The time since wireless activity last occurred.
	Inactive time.Duration

	// The number of bytes received by this station.
	ReceivedBytes int

	// The number of bytes transmitted by this station.
	TransmittedBytes int

	// The number of packets received by this station.
	ReceivedPackets int

	// The number of packets transmitted by this station.
	TransmittedPackets int

	// The current data receive bitrate, in bits/second.
	ReceiveBitrate int

	// The current data transmit bitrate, in bits/second.
	TransmitBitrate int

	// The signal strength of the last received PPDU, in dBm.
	Signal int

	// The average signal strength, in dBm.
	SignalAverage int

	// The number of times the station has had to retry while sending a packet.
	TransmitRetries int

	// The number of times a packet transmission failed.
	TransmitFailed int

	// The number of times a beacon loss was detected.
	BeaconLoss int

	// The current receive rate and detailed modulation information.
	ReceiveRateInfo RateInfo

	// The current transmit rate and detailed modulation information.
	TransmitRateInfo RateInfo
}

// BSSLoad is an Information Element containing measurements of the load on the BSS.
type BSSLoad struct {
	// Version: Indicates the version of the BSS Load Element. Can be 1 or 2.
	Version int

	// StationCount: total number of STA currently associated with this BSS.
	StationCount uint16

	// ChannelUtilization: Percentage of time (linearly scaled 0 to 255) that the AP sensed the medium was busy. Calculated only for the primary channel.
	ChannelUtilization uint8

	// AvailableAdmissionCapacity: remaining amount of medium time available via explicit admission control in units of 32 us/s.
	AvailableAdmissionCapacity uint16
}

// String returns the string representation of a BSSLoad.
func (l BSSLoad) String() string {
	switch l.Version {
	case 1:
		return fmt.Sprintf("BSSLoad Version: %d    stationCount: %d    channelUtilization: %d/255     availableAdmissionCapacity: %d\n",
			l.Version, l.StationCount, l.ChannelUtilization, l.AvailableAdmissionCapacity,
		)
	case 2:
		return fmt.Sprintf("BSSLoad Version: %d    stationCount: %d    channelUtilization: %d/255     availableAdmissionCapacity: %d [*32us/s]\n",
			l.Version, l.StationCount, l.ChannelUtilization, l.AvailableAdmissionCapacity,
		)
	}
	return fmt.Sprintf("invalid BSSLoad Version: %d", l.Version)
}

// A BSS is an 802.11 basic service set.  It contains information about a wireless
// network associated with an Interface.
type BSS struct {
	// The service set identifier, or "network name" of the BSS.
	SSID string

	// BSSID: The BSS service set identifier.  In infrastructure mode, this is the
	// hardware address of the wireless access point that a client is associated
	// with.
	BSSID net.HardwareAddr

	// Frequency: The frequency used by the BSS, in MHz.
	Frequency int

	// BeaconInterval: The time interval between beacon transmissions for this BSS.
	BeaconInterval time.Duration

	// LastSeen: The time since the client last scanned this BSS's information.
	LastSeen time.Duration

	// Status: The status of the client within the BSS.
	Status BSSStatus

	// Signal: The signal strength of the BSS, in mBm (divide by 100 to get dBm).
	Signal int32

	// SignalUnspecified: The signal strength of the BSS, in percent.
	SignalUnspecified uint32

	// Load: The load element of the BSS (contains StationCount, ChannelUtilization and AvailableAdmissionCapacity).
	Load BSSLoad

	// RSN Robust Security Network Information Element (IEEE 802.11 Element ID 48)
	RSN RSNInfo
}

// A BSSStatus indicates the current status of client within a BSS.
type BSSStatus int

const (
	// BSSStatusAuthenticated indicates that a client is authenticated with a BSS.
	BSSStatusAuthenticated BSSStatus = iota

	// BSSStatusAssociated indicates that a client is associated with a BSS.
	BSSStatusAssociated

	// BSSStatusNotAssociated indicates that a client is not associated with a BSS.
	BSSStatusNotAssociated

	// BSSStatusIBSSJoined indicates that a client has joined an independent BSS.
	BSSStatusIBSSJoined
)

// String returns the string representation of a BSSStatus.
func (s BSSStatus) String() string {
	switch s {
	case BSSStatusAuthenticated:
		return "authenticated"
	case BSSStatusAssociated:
		return "associated"
	case BSSStatusNotAssociated:
		return "unassociated"
	case BSSStatusIBSSJoined:
		return "IBSS joined"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// A PHY represents the physical attributes of a wireless device.
type PHY struct {
	// The index of the interface.
	Index int

	// The name of the interface.
	Name string

	// The interface types this device supports.
	SupportedIftypes []InterfaceType

	// The software-only interface types this device supports.
	SoftwareIftypes []InterfaceType

	// An array of attributes related to each radio frequency band.
	BandAttributes []BandAttributes

	// A description of what combinations of interfaces the device can
	// support running simultaneously, on virtual MACs.
	InterfaceCombinations []InterfaceCombination

	// All the attributes the kernel has told us about, but we haven't
	// parsed.
	Extra map[uint16][]byte
}

// BandAttributes represent the RF band-specific attributes.
type BandAttributes struct {
	// High Throughput (802.11n) device capabilities (nil if not supported).
	HTCapabilities *HTCapabilities

	// Very High Throughput (802.11ac) device capabilities (nil if not supported).
	VHTCapabilities *VHTCapabilities

	// High Efficiency (802.11ax) device capabilities for this band (nil if
	// not supported).  Unlike HT and VHT capabilities, which apply to a
	// band as a whole, these also depend on the role an interface operates
	// in, so there is one element for each set of interface types which
	// share the same capabilities.  Find the relevant element by searching
	// its InterfaceTypes field: the order of the elements is chosen by the
	// driver and means nothing.
	HECapabilities []HECapabilities

	// Extremely High Throughput (802.11be) device capabilities for this
	// band (nil if not supported).  As with HECapabilities, there is one
	// element for each set of interface types which share the same
	// capabilities, to be found by searching its InterfaceTypes field
	// rather than by position.
	EHTCapabilities []EHTCapabilities

	// Minimum spacing between A-MPDU frames.  Used for both HT and VHT
	// capable devices.
	MinRxAMPDUSpacing time.Duration

	// Per-frequency (channel) attributes.
	FrequencyAttributes []FrequencyAttrs

	// Per-bitrate attributes.
	BitrateAttributes []BitrateAttrs
}

// HTCapabilities represents 802.11n (High Throughput) capabilities.  This group
// of attributes is specific to each band of frequencies.  Failure to support
// any given attribute may be due to lack support in the driver or the firmware,
// not only in the hardware.  Some of them may also be overridden during station
// association.
//
// The fields represent those in the HT Capabilities element (802.11-2016,
// 9.4.2.56).  Notably missing is information about the device's Spatial
// Multiplexing Power Save (SMPS) capability.  SMPS support must be determined
// by retrieving the device feature flags (not yet supported).
type HTCapabilities struct {
	// Device supports Low Density Parity Check codes.
	RxLDPC bool

	// Device supports 40MHz channels (in addition to 20MHz channels).
	CW40 bool

	// Device supports HT Greenfield (802.11n-only) mode, in which a/b/g
	// frames will be ignored.
	HTGreenfield bool

	// Device supports short guard intervals in 20MHz channels.
	SGI20 bool

	// Device supports short guard intervals in 40MHz channels.
	SGI40 bool

	// Device supports Space-Time Block Coding transmission.
	TxSTBC bool

	// Number of STBC receive streams supported by the device.  Valid values
	// are 0-3.
	RxSTBCStreams uint8

	// Device supports delayed Block Ack frames when acknowledging an
	// A-MPDU.
	HTDelayedBlockAck bool

	// Device supports long (7935 bytes) maximum A-MSDU length, compared to
	// standard 3839 bytes.
	LongMaxAMSDULength bool

	// Device supports DSSS/CCK in 40MHz channels.
	DSSSCCKHT40 bool

	// (2.4GHz) Band cannot tolerate 40MHz channels because someone has
	// requested it support 20MHz channels.
	FortyMhzIntolerant bool

	// Device supports L-SIG (non-HT) Transmit Oppportunity protection.
	LSIGTxOPProtection bool

	// Maximum receivable A-MPDU (Aggregated MAC Protocol Data Unit) frame
	// size.
	MaxRxAMPDULength int

	// The MCS indices the device supports receiving, in ascending order.
	// Indices 0 through 7 use a single spatial stream, 8 through 31 use
	// several with equal modulation, and the remainder use several with
	// unequal modulation.
	RxMCS []int

	// The highest data rate the device supports receiving, in Mb/s.  Zero
	// means the device does not specify one.
	RxHighestRate int

	// Device defines a set of MCS indices for transmission.  The three
	// fields below are only meaningful when this is set.
	TxMCSSetDefined bool

	// The device's transmit MCS set differs from RxMCS, which it does not
	// report.  When this is not set, the device transmits the same indices
	// it receives.
	TxRxMCSSetNotEqual bool

	// The maximum number of spatial streams the device supports for
	// transmission.  Valid values are 1 through 4.  Only meaningful when
	// TxRxMCSSetNotEqual is set.
	TxMaxSpatialStreams int

	// Device supports transmitting with unequal modulation.  Only
	// meaningful when TxRxMCSSetNotEqual is set.
	TxUnequalModulation bool

	// The raw Supported MCS Set field, from which the fields above are
	// decoded (802.11-2020, 9.4.2.55.4).
	SupportedMCS [16]byte
}

// VHTCapabilities represents 802.11ac (Very High Throughput) capabilities.
//
// The fields represent those in the VHT Capabilities element (802.11-2020,
// 9.4.2.157).
type VHTCapabilities struct {
	// Maximum MPDU length supported by the device.
	MaxMPDULength int

	// Device supports 160MHz channel width.
	VHT160 bool

	// Device supports 80+80MHz channel width (non-contiguous 160MHz) along with 160MHz channel.
	VHT8080 bool

	// Device supports receiving Low Density Parity Check codes.
	RXLDPC bool

	// Device supports short guard intervals in 80MHz channels.
	ShortGI80 bool

	// Device supports short guard intervals in 160MHz and 80+80MHz channels.
	ShortGI160 bool

	// Device supports transmission of at least 2x1 Space-Time Block Coding transmission.
	TXSTBC bool

	// Number of STBC receive streams supported by the device. Valid values are 0-4.
	RXSTBC int

	// Device supports SU (Single User) Beamforming as a transmitter.
	SuBeamFormer bool

	// Device supports SU (Single User) Beamforming as a receiver.
	SuBeamFormee bool

	// Number of sounding antennas supported by the device for SU Beamforming transmission.
	BFAntenna int

	// Maximum sounding dimensions supported by the device for SU Beamforming.
	SoundingDimension int

	// Device supports MU (Multi-User) Beamforming as a transmitter.
	MuBeamformer bool

	// Device supports MU (Multi-User) Beamforming as a receiver.
	MuBeamformee bool

	// Device supports VHT TXOP power save mode.
	VTHTXOPPS bool

	// Device supports HT Control field when operating in VHT mode.
	HTCVHT bool

	// Maximum A-MPDU (Aggregated MAC Protocol Data Unit) frame size supported by the device.
	MaxAMPDU int

	// Device supports VHT Link Adaptation capabilities. Valid values
	// specify the type of link adaptation supported (e.g., no feedback,
	// unsolicited feedback, or both).
	VHTLinkAdapt int

	// Device supports receive antenna pattern consistency.
	RXAntennaPattern bool

	// Device supports transmit antenna pattern consistency.
	TXAntennaPattern bool

	//Indicates whether the STA is capable of interpreting the Extended NSS BW
	//Support subfield of the VHT Capabilities Information field.
	ExtendedNSSBW int

	// The highest MCS index the device supports for reception and for
	// transmission with each number of spatial streams, indexed by the
	// number of spatial streams minus one.  Valid values are 7, 8 and 9, or
	// -1 when the device does not support that number of streams.
	RxHighestMCS [8]int
	TxHighestMCS [8]int

	// The highest data rate the device supports for reception and for
	// transmission using a long guard interval, in Mb/s.  Zero means the
	// device does not specify one.
	RxHighestRate int
	TxHighestRate int

	// The maximum total number of space-time streams the device supports
	// receiving.
	MaxNSTSTotal int

	// Device is capable of interpreting the Extended NSS BW Support
	// subfield of another device's VHT Capabilities element.  This is
	// distinct from ExtendedNSSBW above, which is the value of this
	// device's own subfield.
	ExtendedNSSBWCapable bool

	// The raw VHT Supported MCS Set field, from which the fields above are
	// decoded (802.11-2020, 9.4.2.157.3).
	SupportedMCS [8]byte
}

// HECapabilities represents 802.11ax (High Efficiency, WiFi 6) capabilities.
// These are specific to a band, as HT and VHT capabilities are, but 802.11ax
// also allows them to vary with the role an interface operates in, so a band
// may report several sets of them.  Failure to support any given attribute may
// be due to lack of support in the driver or the firmware, not only in the
// hardware.
//
// The fields represent those in the HE Capabilities element (802.11ax,
// 9.4.2.248).
type HECapabilities struct {
	// The interface types these capabilities apply to, which identify this
	// set within its band.  An interface type belongs to at most one set:
	// the kernel refuses to register a device which reports otherwise.
	//
	// Interfaces of type InterfaceTypeAPVLAN are never listed, and use the
	// capabilities reported for InterfaceTypeAP.
	InterfaceTypes []InterfaceType

	// Fields of the HE MAC Capabilities Information field (9.4.2.248.2).

	// Device supports the HT Control field in HE frames.
	HTCHE bool

	// Device supports requesting TWT (Target Wake Time) agreements.
	TWTRequester bool

	// Device supports responding to TWT (Target Wake Time) requests.
	TWTResponder bool

	// The level of dynamic fragmentation the device supports.  Valid values
	// are 0 (not supported) through 3.
	DynamicFragmentation int

	// The maximum number of fragmented MSDUs the device supports, encoded
	// as in 802.11ax: values 0 through 6 indicate 1, 2, 4, 8, 16, 32 and 64
	// fragments, and 7 indicates no limit.
	MaxFragmentedMSDUs int

	// The minimum payload size of a fragment the device supports, in bytes.
	// Zero means the device imposes no restriction.
	MinFragmentSize int

	// The MAC padding duration the device requires for a trigger frame, in
	// microseconds.  Valid values are 0, 8 and 16; the reserved encoding is
	// reported as 0.
	TriggerFrameMACPaddingDuration int

	// The number of TIDs (Traffic Identifiers) the device supports
	// aggregating in a received A-MPDU, minus one.
	MultiTIDAggregationRx int

	// The type of HE link adaptation supported by the device.  Valid values
	// are 0 (no feedback), 2 (unsolicited feedback) and 3 (both solicited
	// and unsolicited feedback).  Only meaningful when HTCHE is set.
	LinkAdaptation int

	// Device supports the All Ack variant of the Multi-STA BlockAck frame.
	AllAck bool

	// Device supports TRS (Triggered Response Scheduling).
	TRS bool

	// Device supports BSR (Buffer Status Report) control.
	BSR bool

	// Device supports broadcast TWT (Target Wake Time).
	BroadcastTWT bool

	// Device supports 32-bit BlockAck bitmaps.
	BA32BitBitmap bool

	// Device supports MU cascading.
	MUCascading bool

	// Device supports ack-enabled aggregation.
	AckEnabledAggregation bool

	// Device supports the OM (Operating Mode) Control subfield.
	OMControl bool

	// Device supports OFDMA random access.
	OFDMARA bool

	// Extension to the maximum A-MPDU (Aggregated MAC Protocol Data Unit)
	// length exponent advertised in the device's HT or VHT capabilities.
	// Valid values are 0 through 3.
	MaxAMPDULengthExponentExt int

	// Device supports A-MSDU fragmentation.
	AMSDUFragmentation bool

	// Device supports flexible TWT (Target Wake Time) scheduling.
	FlexibleTWTScheduling bool

	// Device supports receiving control frames from a different BSS of a
	// multiple BSSID set.
	RxControlFrameToMultiBSS bool

	// Device supports aggregating BSRP (Buffer Status Report Poll) and BQRP
	// (Bandwidth Query Report Poll) frames in an A-MPDU.
	BSRPBQRPAMPDUAggregation bool

	// Device supports the quiet time period.
	QTP bool

	// Device supports the BQR (Bandwidth Query Report) variant of the
	// A-Control field.
	BQR bool

	// Device supports the PSR (Parameterized Spatial Reuse) responder role.
	PSRResponder bool

	// Device supports NDP (Null Data Packet) feedback reports.
	NDPFeedbackReport bool

	// Device supports OPS (Opportunistic Power Save).
	OPS bool

	// Device supports carrying an A-MSDU in an A-MPDU acknowledged by a
	// BlockAck frame.
	AMSDUInAMPDU bool

	// The number of TIDs (Traffic Identifiers) the device supports
	// aggregating in a transmitted A-MPDU, minus one.
	MultiTIDAggregationTx int

	// Device supports HE subchannel selective transmission.
	SubchannelSelectiveTransmission bool

	// Device supports uplink 2x996-tone RUs (Resource Units).
	UL2x996ToneRU bool

	// Device supports disabling uplink MU data reception using the OM
	// Control subfield.
	OMControlULMUDataDisableRx bool

	// Device supports HE dynamic SM (Spatial Multiplexing) power save.
	DynamicSMPowerSave bool

	// Device supports punctured sounding.
	PuncturedSounding bool

	// Device supports receiving trigger frames in HT and VHT PPDUs.
	HTVHTTriggerFrameRx bool

	// Fields of the HE PHY Capabilities Information field (9.4.2.248.3).

	// Device supports 40MHz channels in the 2.4GHz band.
	Support40MHzIn2GHz bool

	// Device supports 40MHz and 80MHz channels in the 5GHz and 6GHz bands.
	Support40MHz80MHzIn5GHz bool

	// Device supports 160MHz channels in the 5GHz and 6GHz bands.
	Support160MHzIn5GHz bool

	// Device supports 80+80MHz channels in the 5GHz and 6GHz bands.
	Support80Plus80MHzIn5GHz bool

	// Device supports 242-tone RUs (Resource Units) in the 2.4GHz band.
	Support242ToneRUIn2GHz bool

	// Device supports 242-tone RUs (Resource Units) in the 5GHz and 6GHz
	// bands.
	Support242ToneRUIn5GHz bool

	// The punctured preamble patterns the device supports receiving, as a
	// bitmap: bits 0 and 1 for 80MHz channels with the secondary 20MHz or
	// 40MHz punctured, and bits 2 and 3 for the same in 160MHz and 80+80MHz
	// channels.
	PuncturedPreambleRx int

	// Device is a class A (rather than class B) device.
	DeviceClassA bool

	// Device supports LDPC (Low Density Parity Check) coding in the
	// payload.
	LDPCCodingInPayload bool

	// Device supports HE SU PPDUs with one HE-LTF (Long Training Field)
	// symbol and a 0.8us guard interval.
	HESUPPDU1xHELTFAnd08usGI bool

	// The maximum number of space-time streams the device supports for
	// receiving a midamble, minus one.
	MidambleRxMaxNSTS int

	// Device supports NDP (Null Data Packet) frames with four HE-LTF
	// symbols and a 3.2us guard interval.
	NDP4xHELTFAnd32usGI bool

	// Device supports transmitting and receiving STBC (Space-Time Block
	// Coding) in channels of 80MHz and below.
	STBCTx80MHz bool
	STBCRx80MHz bool

	// Device supports transmitting and receiving in a Doppler mode.
	DopplerTx bool
	DopplerRx bool

	// Device supports full bandwidth and partial bandwidth UL (uplink)
	// MU-MIMO.  For an access point these indicate reception, and for a
	// station transmission.
	FullBandwidthULMUMIMO    bool
	PartialBandwidthULMUMIMO bool

	// The maximum constellation the device supports for DCM (Dual Carrier
	// Modulation) transmission and reception: 0 (no DCM), 1 (BPSK), 2
	// (QPSK) or 3 (16-QAM).
	DCMMaxConstellationTx int
	DCMMaxConstellationRx int

	// The maximum number of spatial streams the device supports for DCM
	// transmission and reception, minus one.
	DCMMaxNSSTx int
	DCMMaxNSSRx int

	// Device supports receiving a partial bandwidth SU PPDU within a 20MHz
	// HE MU PPDU sent by a station other than an access point.
	RxPartialBandwidthSUIn20MHzMU bool

	// Device supports SU (Single User) beamforming as a transmitter and as
	// a receiver, and MU (Multi User) beamforming as a transmitter.
	SUBeamformer bool
	SUBeamformee bool
	MUBeamformer bool

	// The maximum number of space-time streams the device supports as a
	// beamformee, minus one, in channels of 80MHz and below and in wider
	// channels respectively.
	BeamformeeSTS80MHz      int
	BeamformeeSTSAbove80MHz int

	// The number of sounding dimensions the device supports as a
	// beamformer, minus one, in channels of 80MHz and below and in wider
	// channels respectively.
	SoundingDimensions80MHz      int
	SoundingDimensionsAbove80MHz int

	// Device supports subcarrier grouping of 16 (Ng = 16) for SU and MU
	// beamforming feedback.
	NG16SUFeedback bool
	NG16MUFeedback bool

	// Device supports codebook size (4, 2) for SU beamforming feedback and
	// (7, 5) for MU beamforming feedback.
	Codebook42SUFeedback bool
	Codebook75MUFeedback bool

	// Device supports triggered SU beamforming feedback, triggered MU
	// beamforming partial bandwidth feedback, and triggered CQI (Channel
	// Quality Indicator) feedback.
	TriggeredSUBeamformingFeedback          bool
	TriggeredMUBeamformingPartialBWFeedback bool
	TriggeredCQIFeedback                    bool

	// Device supports partial bandwidth extended range transmission.
	PartialBandwidthExtendedRange bool

	// Device supports partial bandwidth DL (downlink) MU-MIMO.
	PartialBandwidthDLMUMIMO bool

	// PPE (Packet Padding Extension) thresholds are present in
	// PPEThresholds.
	PPEThresholdsPresent bool

	// Device supports PSR (Parameterized Spatial Reuse) based spatial
	// reuse.
	PSRBasedSR bool

	// Device supports the power boost factor.
	PowerBoostFactor bool

	// Device supports HE SU and HE MU PPDUs with four HE-LTF symbols and a
	// 0.8us guard interval.
	HESUMUPPDU4xHELTFAnd08usGI bool

	// The maximum number of columns (Nc) the device supports in a
	// compressed beamforming feedback matrix, minus one.
	MaxNc int

	// Device supports transmitting and receiving STBC (Space-Time Block
	// Coding) in channels wider than 80MHz.
	STBCTxAbove80MHz bool
	STBCRxAbove80MHz bool

	// Device supports HE ER (Extended Range) SU PPDUs with four HE-LTF
	// symbols and a 0.8us guard interval.
	HEERSUPPDU4xHELTFAnd08usGI bool

	// Device supports receiving a 20MHz HE PPDU in a 40MHz channel in the
	// 2.4GHz band.
	Support20MHzIn40MHzHEPPDUIn2GHz bool

	// Device supports receiving a 20MHz or 80MHz HE PPDU in a 160MHz or
	// 80+80MHz channel.
	Support20MHzIn160MHzHEPPDU bool
	Support80MHzIn160MHzHEPPDU bool

	// Device supports HE ER (Extended Range) SU PPDUs with one HE-LTF
	// symbol and a 0.8us guard interval.
	HEERSUPPDU1xHELTFAnd08usGI bool

	// Device supports midamble reception with 2x and 1x HE-LTF symbols.
	MidambleRx2xAnd1xHELTF bool

	// The largest RU (Resource Unit) in which the device supports DCM (Dual
	// Carrier Modulation): 0 (242 tones), 1 (484 tones), 2 (996 tones) or 3
	// (2x996 tones).
	DCMMaxRU int

	// Device supports HE MU PPDUs with more than 16 HE SIG-B OFDM symbols.
	LongerThan16HESIGBOFDMSymbols bool

	// Device supports non-triggered CQI (Channel Quality Indicator)
	// feedback.
	NonTriggeredCQIFeedback bool

	// Device supports transmitting and receiving 1024-QAM in RUs smaller
	// than 242 tones.
	Tx1024QAMLess242ToneRU bool
	Rx1024QAMLess242ToneRU bool

	// Device supports receiving a full bandwidth SU PPDU using an HE MU
	// PPDU with a compressed or non-compressed HE SIG-B field.
	RxFullBWSUUsingMUCompressedSIGB    bool
	RxFullBWSUUsingMUNonCompressedSIGB bool

	// The nominal packet padding the device requires, in microseconds.
	// Valid values are 0, 8 and 16; the reserved encoding is reported as 0.
	NominalPacketPadding int

	// Device limits the number of HE-LTF symbols of an HE MU PPDU with more
	// than one RU to the maximum for its bandwidth.
	HEMUM1RUMaxLTF bool

	// The highest MCS index the device supports for each number of spatial
	// streams, for each channel width it supports.
	SupportedMCSSets []HEMCSNSSSet

	// The raw Supported HE-MCS And NSS Set field, from which
	// SupportedMCSSets is decoded (802.11ax, 9.4.2.248.4).
	SupportedMCS []byte

	// The raw HE PPE Thresholds field (802.11ax, 9.4.2.248.5), or nil when
	// PPEThresholdsPresent is not set.  The kernel reports these as a
	// fixed-size buffer rather than trimming them, so this may hold
	// trailing padding beyond the thresholds themselves.
	//
	// Todo:
	//  - Parse the per-NSS, per-RU thresholds it packs, which also yields
	//    the length of the meaningful data.
	PPEThresholds []byte

	// The device's 6GHz band capabilities, only present for a band in the
	// 6GHz range (nil otherwise).
	HE6GHzCapabilities *HE6GHzCapabilities
}

// An HEMCSNSSSet reports the highest MCS index an 802.11ax device supports for
// each number of spatial streams at a given channel width.
type HEMCSNSSSet struct {
	// The channel width this set applies to: ChannelWidth80, which covers
	// all channels of 80MHz and below, ChannelWidth160 or
	// ChannelWidth80P80.  A device which supports no width beyond 20MHz
	// reports its mandatory first set as ChannelWidth20.
	Width ChannelWidth

	// The highest MCS index the device supports for reception and for
	// transmission with each number of spatial streams, indexed by the
	// number of spatial streams minus one.  Valid values are 7, 9 and 11,
	// or -1 when the device does not support that number of streams.
	RxHighestMCS [8]int
	TxHighestMCS [8]int
}

// HE6GHzCapabilities represents the 802.11ax capabilities which are specific to
// the 6GHz band, in which a device has no HT or VHT capabilities element to
// carry them.
//
// The fields represent those in the HE 6GHz Band Capabilities element
// (802.11ax, 9.4.2.263).
type HE6GHzCapabilities struct {
	// Minimum spacing the device requires between A-MPDU frames.
	MinMPDUStartSpacing time.Duration

	// Maximum receivable A-MPDU (Aggregated MAC Protocol Data Unit) frame
	// size, in bytes.
	MaxRxAMPDULength int

	// Maximum MPDU length supported by the device, in bytes.  The reserved
	// encoding is reported as 0.
	MaxMPDULength int

	// The device's SM (Spatial Multiplexing) power save mode: 0 (static), 1
	// (dynamic), 2 (reserved) or 3 (disabled).
	SMPowerSave int

	// Device supports acting as an RD (Reverse Direction) responder.
	RDResponder bool

	// Device supports receive and transmit antenna pattern consistency.
	RXAntennaPattern bool
	TXAntennaPattern bool
}

// EHTCapabilities represents 802.11be (Extremely High Throughput, WiFi 7)
// capabilities.  These are specific to a band, as HT and VHT capabilities are,
// but 802.11be also allows them to vary with the role an interface operates in,
// so a band may report several sets of them.  Failure to support any given
// attribute may be due to lack of support in the driver or the firmware, not
// only in the hardware.
//
// The fields represent those in the EHT Capabilities element (802.11be,
// 9.4.2.313).
type EHTCapabilities struct {
	// The interface types these capabilities apply to, which identify this
	// set within its band.  An interface type belongs to at most one set:
	// the kernel refuses to register a device which reports otherwise.
	//
	// Interfaces of type InterfaceTypeAPVLAN are never listed, and use the
	// capabilities reported for InterfaceTypeAP.
	InterfaceTypes []InterfaceType

	// Fields of the EHT MAC Capabilities Information field (9.4.2.313.2).

	// Device supports EPCS (Emergency Preparedness Communications Service)
	// priority access.
	EPCSPriorityAccess bool

	// Device supports the EHT OM (Operating Mode) Control subfield.
	OMControl bool

	// Device supports triggered TXOP sharing mode 1, in which the shared
	// TXOP may only be used for non-triggered frame exchanges.
	TriggeredTXOPSharingMode1 bool

	// Device supports triggered TXOP sharing mode 2, in which the shared
	// TXOP may also be used for triggered frame exchanges.
	TriggeredTXOPSharingMode2 bool

	// Device supports restricted TWT (Target Wake Time).
	RestrictedTWT bool

	// Device supports SCS (Stream Classification Service) traffic
	// descriptions.
	SCSTrafficDescription bool

	// Maximum MPDU length supported by the device, in bytes.  The reserved
	// encoding is reported as 0.
	MaxMPDULength int

	// Extension to the maximum A-MPDU (Aggregated MAC Protocol Data Unit)
	// length exponent advertised in the device's HE capabilities.  Valid
	// values are 0 and 1.
	MaxAMPDULengthExponentExt int

	// Device supports the EHT TRS (Triggered Response Scheduling) subfield.
	TRS bool

	// Device supports returning the unused portion of a TXOP shared using
	// triggered TXOP sharing mode 2.
	TXOPReturn bool

	// Device supports two BQRs (Bandwidth Query Reports) in an A-Control
	// field.
	TwoBQRs bool

	// The type of EHT link adaptation supported by the device.  Valid
	// values are 0 (not supported), 2 (unsolicited feedback) and 3 (both
	// solicited and unsolicited feedback).
	LinkAdaptation int

	// Device supports unsolicited EPCS priority access.
	UnsolicitedEPCSPriorityAccess bool

	// Fields of the EHT PHY Capabilities Information field (9.4.2.313.3).

	// Device supports 320MHz channel width in the 6GHz band.
	Support320MHzIn6GHz bool

	// Device supports 242-tone RUs (Resource Units) in channels wider than
	// 20MHz.
	Support242ToneRUWiderThan20MHz bool

	// Device supports NDP (Null Data Packet) frames with four EHT-LTF
	// (Long Training Field) symbols and a 3.2us guard interval.
	NDP4xEHTLTFAnd32usGI bool

	// Device supports partial bandwidth UL (uplink) MU-MIMO.
	PartialBandwidthULMUMIMO bool

	// Device supports SU (Single User) beamforming as a transmitter.
	SUBeamformer bool

	// Device supports SU (Single User) beamforming as a receiver.
	SUBeamformee bool

	// Number of spatial streams the device supports as a beamformee, minus
	// one, in channels of 80MHz and below, of 160MHz and of 320MHz
	// respectively.
	BeamformeeSS80MHz  int
	BeamformeeSS160MHz int
	BeamformeeSS320MHz int

	// Number of sounding dimensions the device supports as a beamformer,
	// minus one, in channels of 80MHz and below, of 160MHz and of 320MHz
	// respectively.
	SoundingDimensions80MHz  int
	SoundingDimensions160MHz int
	SoundingDimensions320MHz int

	// Device supports subcarrier grouping of 16 (Ng = 16) for SU
	// beamforming feedback.
	NG16SUFeedback bool

	// Device supports subcarrier grouping of 16 (Ng = 16) for MU
	// beamforming feedback.
	NG16MUFeedback bool

	// Device supports codebook size (4, 2) for SU beamforming feedback.
	Codebook42SUFeedback bool

	// Device supports codebook size (7, 5) for MU beamforming feedback.
	Codebook75MUFeedback bool

	// Device supports triggered SU beamforming feedback.
	TriggeredSUBeamformingFeedback bool

	// Device supports triggered MU beamforming partial bandwidth feedback.
	TriggeredMUBeamformingPartialBWFeedback bool

	// Device supports triggered CQI (Channel Quality Indicator) feedback.
	TriggeredCQIFeedback bool

	// Device supports partial bandwidth DL (downlink) MU-MIMO.
	PartialBandwidthDLMUMIMO bool

	// Device supports PSR (Parameterized Spatial Reuse) based spatial
	// reuse.
	PSRBasedSR bool

	// Device supports the power boost factor.
	PowerBoostFactor bool

	// Device supports EHT MU PPDUs with four EHT-LTF symbols and a 0.8us
	// guard interval.
	EHTMUPPDU4xEHTLTFAnd08usGI bool

	// Maximum number of columns (Nc) the device supports in a compressed
	// beamforming feedback matrix, minus one.
	MaxNc int

	// Device supports non-triggered CQI feedback.
	NonTriggeredCQIFeedback bool

	// Device supports transmitting 1024-QAM and 4096-QAM in RUs smaller
	// than 242 tones.
	TxLess242ToneRU bool

	// Device supports receiving 1024-QAM and 4096-QAM in RUs smaller than
	// 242 tones.
	RxLess242ToneRU bool

	// PPE (Packet Padding Extension) thresholds are present in
	// PPEThresholds.
	PPEThresholdsPresent bool

	// The common nominal packet padding the device requires, in
	// microseconds.  Valid values are 0, 8, 16 and 20.
	CommonNominalPacketPadding int

	// The Maximum Number Of Supported EHT-LTFs subfield, which encodes the
	// maximum number of EHT-LTF symbols the device supports in an EHT PPDU.
	MaxSupportedEHTLTFs int

	// The bandwidths in which the device supports MCS 15, as a bitmap: bit
	// 0 for MRU sizes up to 80MHz, bits 1 and 2 for 160MHz, and bit 3 for
	// 320MHz.
	MCS15Support int

	// Device supports EHT DUP (duplicate) transmission in the 6GHz band.
	EHTDupIn6GHz bool

	// Device supports receiving an NDP of a wider bandwidth than the
	// operating 20MHz channel.
	Support20MHzRxNDPWiderBandwidth bool

	// Device supports non-OFDMA UL MU-MIMO in channels of 80MHz and below,
	// of 160MHz and of 320MHz respectively.
	NonOFDMAULMUMIMO80MHz  bool
	NonOFDMAULMUMIMO160MHz bool
	NonOFDMAULMUMIMO320MHz bool

	// Device supports MU beamforming in channels of 80MHz and below, of
	// 160MHz and of 320MHz respectively.
	MUBeamformer80MHz  bool
	MUBeamformer160MHz bool
	MUBeamformer320MHz bool

	// Device applies a rate limit to TB (Trigger Based) sounding feedback.
	TBSoundingFeedbackRateLimit bool

	// Device supports receiving 1024-QAM in a DL OFDMA transmission wider
	// than the PPDU bandwidth.
	Rx1024QAMWiderBandwidthDLOFDMA bool

	// Device supports receiving 4096-QAM in a DL OFDMA transmission wider
	// than the PPDU bandwidth.
	Rx4096QAMWiderBandwidthDLOFDMA bool

	// The maximum number of spatial streams the device supports for each
	// range of MCS indices, for each channel width it supports.
	SupportedMCSSets []EHTMCSNSSSet

	// The raw Supported EHT-MCS And NSS Set field, from which
	// SupportedMCSSets is decoded (802.11be, 9.4.2.313.4).
	SupportedMCS []byte

	// The raw EHT PPE Thresholds field (802.11be, 9.4.2.313.5), or nil when
	// PPEThresholdsPresent is not set.
	//
	// Todo:
	//  - Parse the per-NSS, per-RU thresholds it packs.
	PPEThresholds []byte
}

// An EHTMCSNSSSet reports the maximum number of spatial streams an 802.11be
// device supports at a given channel width.
type EHTMCSNSSSet struct {
	// The channel width this set applies to.  ChannelWidth20 indicates the
	// map reported by a station which only supports 20MHz channels, and
	// ChannelWidth80 covers all channels of 80MHz and below.
	Width ChannelWidth

	// The maximum number of spatial streams supported for each range of MCS
	// indices at this channel width.
	MCSRanges []EHTMCSNSS
}

// An EHTMCSNSS reports the maximum number of spatial streams an 802.11be device
// supports for a range of EHT MCS indices.
type EHTMCSNSS struct {
	// The inclusive bounds of the range of MCS indices.
	MinMCS int
	MaxMCS int

	// The maximum number of spatial streams supported for reception and for
	// transmission of the MCS range.  Zero means the range is unsupported.
	RxMaxNSS int
	TxMaxNSS int
}

// FrequencyAttrs represents the attributes of a WiFi frequency/channel.
type FrequencyAttrs struct {
	// Frequency is the radio frequency in MHz.
	Frequency int

	// Disabled indicates that the channel is disabled due to regulatory
	// requirements.
	Disabled bool

	// NoIR indicates that no mechanisms that initiate radiation are
	// permitted on this channel.
	NoIR bool

	// RadarDetection indicates that radar detection is mandatory on this
	// channel.
	RadarDetection bool

	// MaxTxPower gives the maximum transmission power in mBm (100 * dBm).
	MaxTxPower float32
}

// BitrateAttrs represents the attributes of a bitrate.
type BitrateAttrs struct {
	// Bitrate is the bitrate in units of 100kbps.
	Bitrate float32

	// ShortPreamble indicates that a short preamble is supported in the
	// 2.4GHz band.
	ShortPreamble bool
}

// InterfaceCombination represents a group of valid combinations of interface
// types which can be simultaneously supported on a device.
type InterfaceCombination struct {
	CombinationLimits []InterfaceCombinationLimit

	// Total is the maximum number of interfaces that can be created in this
	// group.
	Total int

	// NumChannels is the number of different channels which may be used in
	// this group.
	NumChannels int

	// StaApBiMatch indicates that beacon intervals within this group must
	// all be the same, regardless of interface type.
	StaApBiMatch bool
}

// InterfaceCombinationLimit represents a single combination of interface types
// which may be run simultaneously on a device.
type InterfaceCombinationLimit struct {
	InterfaceTypes []InterfaceType

	// Max is the maximum number of interfaces that can be chosen from the
	// set of interface types in InterfaceTypes.
	Max int
}

// List of 802.11 Information Element types.
const (
	ieSSID    = 0
	ieBSSLoad = 11
	ieRSN     = 48 // Robust Security Network
)

// An ie is an 802.11 information element.
type ie struct {
	ID uint8
	// Length field implied by length of data
	Data []byte
}

// parseIEs parses zero or more ies from a byte slice.
// Reference:
//
//	https://www.safaribooksonline.com/library/view/80211-wireless-networks/0596100523/ch04.html#wireless802dot112-CHP-4-FIG-31
func parseIEs(b []byte) ([]ie, error) {
	var ies []ie
	var i int
	for len(b[i:]) != 0 {

		if len(b[i:]) < 2 {
			return nil, errInvalidIE
		}

		id := b[i]
		i++
		l := int(b[i])
		i++

		if len(b[i:]) < l {
			return nil, errInvalidIE
		}

		ies = append(ies, ie{
			ID:   id,
			Data: b[i : i+l],
		})

		i += l
	}

	return ies, nil
}

type SurveyInfo struct {
	// The interface that this station is associated with.
	InterfaceIndex int

	// The frequency in MHz of the channel.
	Frequency int

	// The noise level in dBm.
	Noise int

	// The time the radio has spent on this channel.
	ChannelTime time.Duration

	// The time the radio has spent on this channel while it was active.
	ChannelTimeActive time.Duration

	// The time the radio has spent on this channel while it was busy.
	ChannelTimeBusy time.Duration

	// The time the radio has spent on this channel while it was busy with external traffic.
	ChannelTimeExtBusy time.Duration

	// The time the radio has spent on this channel receiving data from a BSS.
	ChannelTimeBssRx time.Duration

	// The time the radio has spent on this channel receiving data.
	ChannelTimeRx time.Duration

	// The time the radio has spent on this channel transmitting data.
	ChannelTimeTx time.Duration

	// The time the radio has spent on this channel while it was scanning.
	ChannelTimeScan time.Duration

	// Indicates if the channel is currently in use.
	InUse bool
}

// RSNCipher represents a cipher suite in RSN IE.
// Values correspond to OUIs (00-0F-AC-XX) in the wire format as defined in
// IEEE 802.11-2020 standard, section 9.4.2.24.2 (Cipher Suites).
type RSNCipher uint32

const (
	RSNCipherUseGroup        RSNCipher = 0x000FAC00 // Use group cipher suite
	RSNCipherWEP40           RSNCipher = 0x000FAC01 // WEP-40 (insecure, legacy)
	RSNCipherTKIP            RSNCipher = 0x000FAC02 // TKIP (insecure, deprecated)
	RSNCipherReserved3       RSNCipher = 0x000FAC03 // Reserved
	RSNCipherCCMP128         RSNCipher = 0x000FAC04 // CCMP-128 (AES) - WPA2
	RSNCipherWEP104          RSNCipher = 0x000FAC05 // WEP-104 (insecure, legacy)
	RSNCipherBIPCMAC128      RSNCipher = 0x000FAC06 // BIP-CMAC-128 (802.11w MFP/PMF)
	RSNCipherGroupNotAllowed RSNCipher = 0x000FAC07 // Group addressed traffic not allowed
	RSNCipherGCMP128         RSNCipher = 0x000FAC08 // GCMP-128 (AES-GCMP) - WPA3
	RSNCipherGCMP256         RSNCipher = 0x000FAC09 // GCMP-256 (AES-GCMP) - WPA3-Enterprise
	RSNCipherCCMP256         RSNCipher = 0x000FAC0A // CCMP-256 (AES, 256-bit key)
	RSNCipherBIPGMAC128      RSNCipher = 0x000FAC0B // BIP-GMAC-128
	RSNCipherBIPGMAC256      RSNCipher = 0x000FAC0C // BIP-GMAC-256
	RSNCipherBIPCMAC256      RSNCipher = 0x000FAC0D // BIP-CMAC-256
)

// String returns the human-readable name of the RSN cipher.
func (c RSNCipher) String() string {
	switch c {
	case RSNCipherUseGroup:
		return "Use‑group"
	case RSNCipherWEP40:
		return "WEP‑40"
	case RSNCipherTKIP:
		return "TKIP"
	case RSNCipherReserved3:
		return "Reserved‑3"
	case RSNCipherCCMP128:
		return "CCMP‑128"
	case RSNCipherWEP104:
		return "WEP‑104"
	case RSNCipherBIPCMAC128:
		return "BIP‑CMAC‑128"
	case RSNCipherGroupNotAllowed:
		return "Group‑not‑allowed"
	case RSNCipherGCMP128:
		return "GCMP‑128"
	case RSNCipherGCMP256:
		return "GCMP‑256"
	case RSNCipherCCMP256:
		return "CCMP‑256"
	case RSNCipherBIPGMAC128:
		return "BIP‑GMAC‑128"
	case RSNCipherBIPGMAC256:
		return "BIP‑GMAC‑256"
	case RSNCipherBIPCMAC256:
		return "BIP‑CMAC‑256"
	default:
		return fmt.Sprintf("Unknown-0x%08X", uint32(c))
	}
}

// RSNAKM represents an Authentication and Key Management suite in RSN IE.
// Values correspond to OUIs (00-0F-AC-XX) in the wire format as defined in
// IEEE 802.11-2020 standard, section 9.4.2.24.3 (AKM Suites).
type RSNAKM uint32

// RSN AKM suite constants (Wi-Fi Alliance OUI: 00-0F-AC)
const (
	RSNAkmReserved0     RSNAKM = 0x000FAC00 // Reserved
	RSNAkm8021X         RSNAKM = 0x000FAC01 // 802.1X (WPA-Enterprise)
	RSNAkmPSK           RSNAKM = 0x000FAC02 // PSK (WPA2-Personal)
	RSNAkmFT8021X       RSNAKM = 0x000FAC03 // FT-802.1X (Fast BSS transition with EAP)
	RSNAkmFTPSK         RSNAKM = 0x000FAC04 // FT-PSK (Fast BSS transition with PSK)
	RSNAkm8021XSHA256   RSNAKM = 0x000FAC05 // 802.1X-SHA256 (WPA2 with SHA256 auth)
	RSNAkmPSKSHA256     RSNAKM = 0x000FAC06 // PSK-SHA256 (WPA2-PSK with SHA256)
	RSNAkmTDLS          RSNAKM = 0x000FAC07 // TDLS TPK handshake
	RSNAkmSAE           RSNAKM = 0x000FAC08 // SAE (WPA3-Personal)
	RSNAkmFTSAE         RSNAKM = 0x000FAC09 // FT-SAE (WPA3-Personal with Fast Roaming)
	RSNAkmAPPeerKey     RSNAKM = 0x000FAC0A // APPeerKey Authentication with SHA-256
	RSNAkm8021XSuiteB   RSNAKM = 0x000FAC0B // 802.1X using Suite B compliant EAP (SHA-256)
	RSNAkm8021XCNSA     RSNAKM = 0x000FAC0C // 802.1X using CNSA Suite compliant EAP (SHA-384)
	RSNAkmFT8021XSHA384 RSNAKM = 0x000FAC0D // FT-802.1X using SHA-384
	RSNAkmFILSSHA256    RSNAKM = 0x000FAC0E // FILS key management using SHA-256
	RSNAkmFILSSHA384    RSNAKM = 0x000FAC0F // FILS key management using SHA-384
	RSNAkmFTFILSSHA256  RSNAKM = 0x000FAC10 // FT authentication over FILS with SHA-256
	RSNAkmFTFILSSHA384  RSNAKM = 0x000FAC11 // FT authentication over FILS with SHA-384
	RSNAkmReserved18    RSNAKM = 0x000FAC12 // Reserved
	RSNAkmFTPSKSHA384   RSNAKM = 0x000FAC13 // FT-PSK using SHA-384
	RSNAkmPSKSHA384     RSNAKM = 0x000FAC14 // PSK using SHA-384
)

// String returns the human-readable name of the RSN AKM.
func (a RSNAKM) String() string {
	switch a {
	case RSNAkmReserved0:
		return "Reserved‑0"
	case RSNAkm8021X:
		return "802.1X"
	case RSNAkmPSK:
		return "PSK"
	case RSNAkmFT8021X:
		return "FT‑802.1X"
	case RSNAkmFTPSK:
		return "FT‑PSK"
	case RSNAkm8021XSHA256:
		return "802.1X‑SHA256"
	case RSNAkmPSKSHA256:
		return "PSK‑SHA256"
	case RSNAkmTDLS:
		return "TDLS"
	case RSNAkmSAE:
		return "SAE"
	case RSNAkmFTSAE:
		return "FT‑SAE"
	case RSNAkmAPPeerKey:
		return "AP‑PeerKey"
	case RSNAkm8021XSuiteB:
		return "802.1X‑Suite‑B"
	case RSNAkm8021XCNSA:
		return "802.1X‑CNSA"
	case RSNAkmFT8021XSHA384:
		return "FT‑802.1X‑SHA384"
	case RSNAkmFILSSHA256:
		return "FILS‑SHA256"
	case RSNAkmFILSSHA384:
		return "FILS‑SHA384"
	case RSNAkmFTFILSSHA256:
		return "FT‑FILS‑SHA256"
	case RSNAkmFTFILSSHA384:
		return "FT‑FILS‑SHA384"
	case RSNAkmReserved18:
		return "Reserved‑18"
	case RSNAkmFTPSKSHA384:
		return "FT‑PSK‑SHA384"
	case RSNAkmPSKSHA384:
		return "PSK‑SHA384"
	default:
		return fmt.Sprintf("Unknown-0x%08X", uint32(a))
	}
}

// Robust Security Network Information Element
// The RSN IE structure is defined in IEEE 802.11-2020 standard, section 9.4.2.24 (page 1051) .
type RSNInfo struct {
	Version         uint16
	GroupCipher     RSNCipher   // Group cipher suite
	PairwiseCiphers []RSNCipher // Pairwise cipher suites
	AKMs            []RSNAKM    // Authentication and Key Management suites
	Capabilities    uint16      // RSN capability flags
	GroupMgmtCipher RSNCipher   // Group management cipher (present only with WPA3/802.11w)
}

func (r RSNInfo) IsInitialized() bool {
	return r.Version != 0
}

func (r RSNInfo) String() string {
	if !r.IsInitialized() {
		return ""
	}

	// Convert pairwise ciphers to strings
	pairwiseNames := make([]string, len(r.PairwiseCiphers))
	for i, cipher := range r.PairwiseCiphers {
		pairwiseNames[i] = cipher.String()
	}

	// Convert AKMs to strings
	akmNames := make([]string, len(r.AKMs))
	for i, akm := range r.AKMs {
		akmNames[i] = akm.String()
	}

	return fmt.Sprintf(
		"RSN v%d  Group:%s  Pairwise:%v  AKM:%v",
		r.Version, r.GroupCipher.String(), pairwiseNames, akmNames)
}

// RegulatoryDomain contains information about the regulatory domain the device or system operates in.
type RegulatoryDomain struct {
	Region string // ISO 3166-1 alpha-2 country code
}

// RegulatoryHint describes why the regulatory region is being set.
// See:
// - https://wireless.docs.kernel.org/en/latest/en/developers/regulatory/processing_rules.html#cellular-base-station-regulatory-hints
// - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/nl80211.h?h=a55f7f5f29b32c2c53cc291899cf9b0c25a07f7c#n4803
type RegulatoryHint uint32

const (
	RegulatoryHintUser     RegulatoryHint = 0x0 // Set by the userspace (default)
	RegulatoryHintCellBase RegulatoryHint = 0x1 // Set based on cellular network information
	RegulatoryHintIndoor   RegulatoryHint = 0x2 // Set because the device is indoors
)
