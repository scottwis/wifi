//go:build linux

package wifi

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

func TestLinux_clientInterfacesOK(t *testing.T) {
	want := []*Interface{
		{
			Index:        1,
			Name:         "wlan0",
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			PHY:          0,
			Device:       1,
			Type:         InterfaceTypeStation,
			Frequency:    2412,
			ChannelWidth: ChannelWidth80,
		},
		{
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xae},
			PHY:          0,
			Device:       2,
			Type:         InterfaceTypeP2PDevice,
		},
	}

	const flags = netlink.Request | netlink.Dump

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_INTERFACE, flags,
		mustMessages(t, unix.NL80211_CMD_NEW_INTERFACE, want),
	))

	got, err := c.Interfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected interfaces (-want +got):\n%s", diff)
	}
}

func TestLinux_clientBSSMissingBSSAttributeIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// One message without BSS attribute
		return []genetlink.Message{{
			Header: genetlink.Header{
				Command: unix.NL80211_CMD_NEW_SCAN_RESULTS,
			},
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NL80211_ATTR_IFINDEX,
				Data: nlenc.Uint32Bytes(1),
			}}),
		}}, nil
	})

	_, err := c.BSS(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientBSSMissingBSSStatusAttributeIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return []genetlink.Message{{
			Header: genetlink.Header{
				Command: unix.NL80211_CMD_NEW_SCAN_RESULTS,
			},
			// BSS attribute, but no nested status attribute for the "active" BSS
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NL80211_ATTR_BSS,
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: unix.NL80211_BSS_BSSID,
					Data: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				}}),
			}}),
		}}, nil
	})

	_, err := c.BSS(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientBSSNoMessagesIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// No messages about the BSS at the generic netlink level.
		// Caller will interpret this as no BSS.
		return nil, io.EOF
	})

	_, err := c.BSS(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientBSSOKSkipMissingStatus(t *testing.T) {
	want := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return []genetlink.Message{
			// Multiple messages, but only second one has BSS status, so the
			// others should be ignored
			{
				Header: genetlink.Header{
					Command: unix.NL80211_CMD_NEW_SCAN_RESULTS,
				},
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: unix.NL80211_ATTR_BSS,
					// Does not contain BSS information and status
					Data: mustMarshalAttributes([]netlink.Attribute{{
						Type: unix.NL80211_BSS_BSSID,
						Data: net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
					}}),
				}}),
			},
			{
				Header: genetlink.Header{
					Command: unix.NL80211_CMD_NEW_SCAN_RESULTS,
				},
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: unix.NL80211_ATTR_BSS,
					// Contains BSS information and status
					Data: mustMarshalAttributes([]netlink.Attribute{
						{
							Type: unix.NL80211_BSS_BSSID,
							Data: want,
						},
						{
							Type: unix.NL80211_BSS_STATUS,
							Data: nlenc.Uint32Bytes(uint32(BSSStatusAssociated)),
						},
					}),
				}}),
			},
		}, nil
	})

	bss, err := c.BSS(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := bss.BSSID; !bytes.Equal(want, got) {
		t.Fatalf("unexpected BSS BSSID:\n- want: %#v\n-  got: %#v",
			want, got)
	}
}

func TestLinux_clientBSSOK(t *testing.T) {
	want := &BSS{
		SSID:              "Hello, 世界",
		BSSID:             net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		Frequency:         2492,
		BeaconInterval:    100 * 1024 * time.Microsecond,
		LastSeen:          10 * time.Second,
		Status:            BSSStatusAssociated,
		Signal:            -5700,
		SignalUnspecified: 80,
	}

	ifi := &Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	}

	const flags = netlink.Request | netlink.Dump

	msgsFn := mustMessages(t, unix.NL80211_CMD_NEW_SCAN_RESULTS, want)

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_SCAN, flags,
		func(greq genetlink.Message, nreq netlink.Message) ([]genetlink.Message, error) {
			// Also verify that the correct interface attributes are
			// present in the request.
			attrs, err := netlink.UnmarshalAttributes(greq.Data)
			if err != nil {
				t.Fatalf("failed to unmarshal attributes: %v", err)
			}

			if diff := diffNetlinkAttributes(ifi.idAttrs(), attrs); diff != "" {
				t.Fatalf("unexpected request netlink attributes (-want +got):\n%s", diff)
			}

			return msgsFn(greq, nreq)
		},
	))

	got, err := c.BSS(ifi)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected BSS:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestLinux_clientStationInfoMissingAttributeIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// One message without station info attribute
		return []genetlink.Message{{
			Header: genetlink.Header{
				Command: unix.NL80211_CMD_NEW_STATION,
			},
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NL80211_ATTR_IFINDEX,
				Data: nlenc.Uint32Bytes(1),
			}}),
		}}, nil
	})

	_, err := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientStationInfoNoMessagesIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// No messages about station info at the generic netlink level.
		// Caller will interpret this as no station info.
		return nil, io.EOF
	})

	info, err := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if err != nil {
		t.Fatalf("undexpected error: %v", err)
	}
	if !reflect.DeepEqual(info, []*StationInfo{}) {
		t.Fatalf("expected info to be an empty slice, got %v", info)
	}
}

func TestLinux_clientStationInfoOK(t *testing.T) {
	want := []*StationInfo{
		{
			InterfaceIndex:     1,
			HardwareAddr:       net.HardwareAddr{0xb8, 0x27, 0xeb, 0xd5, 0xf3, 0xef},
			Connected:          30 * time.Minute,
			Inactive:           4 * time.Millisecond,
			ReceivedBytes:      1000,
			TransmittedBytes:   2000,
			ReceivedPackets:    10,
			TransmittedPackets: 20,
			Signal:             -50,
			SignalAverage:      -53,
			TransmitRetries:    5,
			TransmitFailed:     2,
			BeaconLoss:         3,
			ReceiveBitrate:     130000000,
			TransmitBitrate:    130000000,
			ReceiveRateInfo:    RateInfo{Bitrate: 130000000, ModulationType: RateModulationInfoTypeVHT, Modulation: VHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 5, NSS: 2}, ShortGI: true}, ChannelWidth: ChannelWidth80P80},
			TransmitRateInfo:   RateInfo{Bitrate: 130000000, ModulationType: RateModulationInfoTypeVHT, Modulation: VHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 3, NSS: 1}, ShortGI: true}, ChannelWidth: ChannelWidth40},
		},
		{
			InterfaceIndex:     1,
			HardwareAddr:       net.HardwareAddr{0x40, 0xa5, 0xef, 0xd9, 0x96, 0x6f},
			Connected:          60 * time.Minute,
			Inactive:           8 * time.Millisecond,
			ReceivedBytes:      2000,
			TransmittedBytes:   4000,
			ReceivedPackets:    20,
			TransmittedPackets: 40,
			Signal:             -25,
			SignalAverage:      -27,
			TransmitRetries:    10,
			TransmitFailed:     4,
			BeaconLoss:         6,
			ReceiveBitrate:     260000000,
			TransmitBitrate:    240000000,
			ReceiveRateInfo:    RateInfo{Bitrate: 260000000, ModulationType: RateModulationInfoTypeVHT, Modulation: VHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 5, NSS: 2}, ShortGI: true}, ChannelWidth: ChannelWidth80},
			TransmitRateInfo:   RateInfo{Bitrate: 240000000, ModulationType: RateModulationInfoTypeVHT, Modulation: VHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 3, NSS: 1}, ShortGI: false}, ChannelWidth: ChannelWidth160},
		},
		{
			InterfaceIndex:     1,
			HardwareAddr:       net.HardwareAddr{0x40, 0xa5, 0xef, 0xd9, 0x96, 0x6f},
			Connected:          60 * time.Minute,
			Inactive:           8 * time.Millisecond,
			ReceivedBytes:      2000,
			TransmittedBytes:   4000,
			ReceivedPackets:    20,
			TransmittedPackets: 40,
			Signal:             -25,
			SignalAverage:      -27,
			TransmitRetries:    10,
			TransmitFailed:     4,
			BeaconLoss:         6,
			ReceiveBitrate:     260000000,
			TransmitBitrate:    240000000,
			ReceiveRateInfo:    RateInfo{Bitrate: 260000000, ModulationType: RateModulationInfoTypeEHT, Modulation: EHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 5, NSS: 2}, GI: 22, RUAlloc: 33}, ChannelWidth: ChannelWidth320},
			TransmitRateInfo:   RateInfo{Bitrate: 240000000, ModulationType: RateModulationInfoTypeHE, Modulation: HEModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 3, NSS: 1}, GI: 1, DCM: 2, RUAlloc: 3}, ChannelWidth: ChannelWidth160},
		},
		{
			InterfaceIndex:     3,
			HardwareAddr:       net.HardwareAddr{0x40, 0xa5, 0xef, 0xd9, 0x96, 0x6f},
			Connected:          40 * time.Minute,
			Inactive:           5 * time.Millisecond,
			ReceivedBytes:      5000,
			TransmittedBytes:   2000,
			ReceivedPackets:    20,
			TransmittedPackets: 40,
			Signal:             -25,
			SignalAverage:      -27,
			TransmitRetries:    10,
			TransmitFailed:     4,
			BeaconLoss:         6,
			ReceiveBitrate:     260000000,
			TransmitBitrate:    240000000,
			ReceiveRateInfo:    RateInfo{Bitrate: 260000000, ModulationType: RateModulationInfoTypeHT, Modulation: HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 6, NSS: 2}, HTMCS: 14, ShortGI: true}, ChannelWidth: ChannelWidth16},
			TransmitRateInfo:   RateInfo{Bitrate: 240000000, ModulationType: RateModulationInfoTypeHT, Modulation: HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 7, NSS: 1}, HTMCS: 7, ShortGI: false}, ChannelWidth: ChannelWidth4},
		},
		{
			InterfaceIndex:     3,
			HardwareAddr:       net.HardwareAddr{0x40, 0xa5, 0xef, 0xd9, 0x96, 0x6f},
			Connected:          40 * time.Minute,
			Inactive:           5 * time.Millisecond,
			ReceivedBytes:      5000,
			TransmittedBytes:   2000,
			ReceivedPackets:    20,
			TransmittedPackets: 40,
			Signal:             -25,
			SignalAverage:      -27,
			TransmitRetries:    10,
			TransmitFailed:     4,
			BeaconLoss:         6,
			ReceiveBitrate:     260000000,
			TransmitBitrate:    240000000,
			ReceiveRateInfo:    RateInfo{Bitrate: 260000000, ModulationType: RateModulationInfoTypeHT, Modulation: HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 6, NSS: 2}, HTMCS: 14, ShortGI: true}, ChannelWidth: ChannelWidth1},
			TransmitRateInfo:   RateInfo{Bitrate: 240000000, ModulationType: RateModulationInfoTypeHT, Modulation: HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 7, NSS: 1}, HTMCS: 7, ShortGI: false}, ChannelWidth: ChannelWidth2},
		},
		{
			InterfaceIndex:     3,
			HardwareAddr:       net.HardwareAddr{0x40, 0xa5, 0xef, 0xd9, 0x96, 0x6f},
			Connected:          40 * time.Minute,
			Inactive:           5 * time.Millisecond,
			ReceivedBytes:      5000,
			TransmittedBytes:   2000,
			ReceivedPackets:    20,
			TransmittedPackets: 40,
			Signal:             -25,
			SignalAverage:      -27,
			TransmitRetries:    10,
			TransmitFailed:     4,
			BeaconLoss:         6,
			ReceiveBitrate:     260000000,
			TransmitBitrate:    240000000,
			ReceiveRateInfo:    RateInfo{Bitrate: 260000000, ModulationType: RateModulationInfoTypeHT, Modulation: HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 6, NSS: 2}, HTMCS: 14, ShortGI: true}, ChannelWidth: ChannelWidth8},
			TransmitRateInfo:   RateInfo{Bitrate: 240000000, ModulationType: RateModulationInfoTypeHT, Modulation: HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 7, NSS: 1}, HTMCS: 7, ShortGI: false}, ChannelWidth: ChannelWidth8},
		},
	}

	ifi := &Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	}

	const flags = netlink.Request | netlink.Dump

	msgsFn := mustMessages(t, unix.NL80211_CMD_NEW_STATION, want)

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_STATION, flags,
		func(greq genetlink.Message, nreq netlink.Message) ([]genetlink.Message, error) {
			// Also verify that the correct interface attributes are
			// present in the request.
			attrs, err := netlink.UnmarshalAttributes(greq.Data)
			if err != nil {
				t.Fatalf("failed to unmarshal attributes: %v", err)
			}

			if diff := diffNetlinkAttributes(ifi.idAttrs(), attrs); diff != "" {
				t.Fatalf("unexpected request netlink attributes (-want +got):\n%s", diff)
			}

			return msgsFn(greq, nreq)
		},
	))

	got, err := c.StationInfo(ifi)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	for i := range want {
		if !reflect.DeepEqual(want[i], got[i]) {
			t.Fatalf("unexpected station info:\n- want: %v\n-  got: %v",
				want[i], got[i])
		}
	}
}

func TestLinux_initClientErrorCloseConn(t *testing.T) {
	c := genltest.Dial(func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// Assume that nl80211 does not exist on this system.
		// The genetlink Conn should be closed to avoid leaking file descriptors.
		return nil, genltest.Error(int(syscall.ENOENT))
	})

	if _, err := initClient(c); err == nil {
		t.Fatal("no error occurred, but expected one")
	}
}

const familyID = 26

func testClient(t *testing.T, fn genltest.Func) *client {
	family := genetlink.Family{
		ID:      familyID,
		Name:    unix.NL80211_GENL_NAME,
		Version: 1,
	}

	c := genltest.Dial(genltest.ServeFamily(family, func(greq genetlink.Message, nreq netlink.Message) ([]genetlink.Message, error) {
		// If this function is invoked, we are calling a nl80211 function.
		if diff := cmp.Diff(int(family.ID), int(nreq.Header.Type)); diff != "" {
			t.Fatalf("unexpected generic netlink family ID (-want +got):\n%s", diff)
		}

		if diff := cmp.Diff(family.Version, greq.Header.Version); diff != "" {
			t.Fatalf("unexpected generic netlink family version (-want +got):\n%s", diff)
		}

		msgs, err := fn(greq, nreq)
		if err != nil {
			return nil, err
		}

		// Do a favor for the caller by planting the correct version in each message
		// header, as long as no version is supplied.
		for i := range msgs {
			if msgs[i].Header.Version == 0 {
				msgs[i].Header.Version = family.Version
			}
		}

		return msgs, nil
	}))

	client, err := initClient(c)
	if err != nil {
		t.Fatalf("failed to initialize test client: %v", err)
	}

	return client
}

// diffNetlinkAttributes compares two []netlink.Attributes after zeroing their
// length fields that make equality checks in testing difficult.
func diffNetlinkAttributes(want, got []netlink.Attribute) string {
	// If different lengths, diff immediately for better error output.
	if len(want) != len(got) {
		return cmp.Diff(want, got)
	}

	for i := range want {
		want[i].Length = 0
		got[i].Length = 0
	}

	return cmp.Diff(want, got)
}

// Helper functions for converting types back into their raw attribute formats

func marshalIEs(ies []ie) []byte {
	buf := bytes.NewBuffer(nil)
	for _, ie := range ies {
		buf.WriteByte(ie.ID)
		buf.WriteByte(uint8(len(ie.Data)))
		buf.Write(ie.Data)
	}

	return buf.Bytes()
}

func mustMarshalAttributes(attrs []netlink.Attribute) []byte {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal attributes: %v", err))
	}

	return b
}

type attributeser interface {
	attributes() []netlink.Attribute
}

var (
	_ attributeser = &Interface{}
	_ attributeser = &BSS{}
	_ attributeser = &StationInfo{}
)

func (ifi *Interface) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		{Type: unix.NL80211_ATTR_IFINDEX, Data: nlenc.Uint32Bytes(uint32(ifi.Index))},
		{Type: unix.NL80211_ATTR_IFNAME, Data: nlenc.Bytes(ifi.Name)},
		{Type: unix.NL80211_ATTR_MAC, Data: ifi.HardwareAddr},
		{Type: unix.NL80211_ATTR_WIPHY, Data: nlenc.Uint32Bytes(uint32(ifi.PHY))},
		{Type: unix.NL80211_ATTR_IFTYPE, Data: nlenc.Uint32Bytes(uint32(ifi.Type))},
		{Type: unix.NL80211_ATTR_WDEV, Data: nlenc.Uint64Bytes(uint64(ifi.Device))},
		{Type: unix.NL80211_ATTR_WIPHY_FREQ, Data: nlenc.Uint32Bytes(uint32(ifi.Frequency))},
		{Type: unix.NL80211_ATTR_CHANNEL_WIDTH, Data: nlenc.Uint32Bytes(uint32(ifi.ChannelWidth))},
	}
}

func (b *BSS) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		// TODO(mdlayher): return more attributes for validation?
		{
			Type: unix.NL80211_ATTR_BSS,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: unix.NL80211_BSS_BSSID, Data: b.BSSID},
				{Type: unix.NL80211_BSS_FREQUENCY, Data: nlenc.Uint32Bytes(uint32(b.Frequency))},
				{Type: unix.NL80211_BSS_BEACON_INTERVAL, Data: nlenc.Uint16Bytes(uint16(b.BeaconInterval / 1024 / time.Microsecond))},
				{Type: unix.NL80211_BSS_SEEN_MS_AGO, Data: nlenc.Uint32Bytes(uint32(b.LastSeen / time.Millisecond))},
				{Type: unix.NL80211_BSS_STATUS, Data: nlenc.Uint32Bytes(uint32(b.Status))},
				{Type: unix.NL80211_BSS_SIGNAL_MBM, Data: nlenc.Int32Bytes(int32(b.Signal))},
				{Type: unix.NL80211_BSS_SIGNAL_UNSPEC, Data: nlenc.Uint32Bytes(uint32(b.SignalUnspecified))},
				{
					Type: unix.NL80211_BSS_INFORMATION_ELEMENTS,
					Data: marshalIEs([]ie{{
						ID:   ieSSID,
						Data: []byte(b.SSID),
					}}),
				},
			}),
		},
	}
}

type rateModulationMarshaler interface {
	marshal() []netlink.Attribute
}

var (
	_ rateModulationMarshaler = BaseModulationInfo{}
	_ rateModulationMarshaler = HTModulationInfo{}
	_ rateModulationMarshaler = VHTModulationInfo{}
	_ rateModulationMarshaler = HEModulationInfo{}
	_ rateModulationMarshaler = EHTModulationInfo{}
)

func (mi BaseModulationInfo) marshal() []netlink.Attribute { return nil }

func (mi HTModulationInfo) marshal() (attr []netlink.Attribute) {
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_MCS, Data: []byte{uint8(mi.HTMCS)}})
	if mi.ShortGI {
		attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_SHORT_GI})
	}

	return attr
}

func (mi VHTModulationInfo) marshal() (attr []netlink.Attribute) {
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_VHT_MCS, Data: []byte{uint8(mi.MCS)}})
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_VHT_NSS, Data: []byte{uint8(mi.NSS)}})
	if mi.ShortGI {
		attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_SHORT_GI})
	}

	return attr
}

func (mi HEModulationInfo) marshal() (attr []netlink.Attribute) {
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_HE_MCS, Data: []byte{uint8(mi.MCS)}})
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_HE_NSS, Data: []byte{uint8(mi.NSS)}})
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_HE_GI, Data: []byte{uint8(mi.GI)}})
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_HE_DCM, Data: []byte{uint8(mi.DCM)}})
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_HE_RU_ALLOC, Data: []byte{uint8(mi.RUAlloc)}})

	return attr
}

func (mi EHTModulationInfo) marshal() (attr []netlink.Attribute) {
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_EHT_MCS, Data: []byte{uint8(mi.MCS)}})
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_EHT_NSS, Data: []byte{uint8(mi.NSS)}})
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_EHT_GI, Data: []byte{uint8(mi.GI)}})
	attr = append(attr, netlink.Attribute{Type: unix.NL80211_RATE_INFO_EHT_RU_ALLOC, Data: []byte{uint8(mi.RUAlloc)}})

	return attr
}

func modulationAttributes(rateInfo RateModulationInfo) []netlink.Attribute {
	if rateInfo == nil {
		return nil
	}

	mod, ok := rateInfo.(rateModulationMarshaler)
	if !ok {
		return nil
	}

	return mod.marshal()
}

func channelWithAttributes(cw ChannelWidth) (attr []netlink.Attribute) {
	switch cw {
	case ChannelWidth20NoHT:
		return attr
	case ChannelWidth20:
		return attr
	case ChannelWidth40:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_40_MHZ_WIDTH}}
	case ChannelWidth80:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_80_MHZ_WIDTH}}
	case ChannelWidth80P80:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_80P80_MHZ_WIDTH}}
	case ChannelWidth160:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_160_MHZ_WIDTH}}
	case ChannelWidth5:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_5_MHZ_WIDTH}}
	case ChannelWidth10:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_10_MHZ_WIDTH}}
	case ChannelWidth1:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_1_MHZ_WIDTH}}
	case ChannelWidth2:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_2_MHZ_WIDTH}}
	case ChannelWidth4:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_4_MHZ_WIDTH}}
	case ChannelWidth8:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_8_MHZ_WIDTH}}
	case ChannelWidth16:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_16_MHZ_WIDTH}}
	case ChannelWidth320:
		return []netlink.Attribute{{Type: unix.NL80211_RATE_INFO_320_MHZ_WIDTH}}
	default:
		return attr
	}
}

func Test_modulationAttributes(t *testing.T) {
	tests := []struct {
		name           string
		in             RateModulationInfo
		wantAttrs      []netlink.Attribute
		wantType       RateModulationInfoType
		wantModulation RateModulationInfo
	}{
		{
			name:           "nil",
			in:             nil,
			wantAttrs:      nil,
			wantType:       RateModulationInfoTypeLegacy,
			wantModulation: nil,
		},
		{
			// BaseModulationInfo isn't marshaled to any netlink attributes, so
			// parseRateInfo sees no modulation-specific attributes at all and
			// falls back to legacy/no modulation, same as the nil case.
			name:           "base modulation",
			in:             BaseModulationInfo{MCS: 1, NSS: 1},
			wantAttrs:      nil,
			wantType:       RateModulationInfoTypeLegacy,
			wantModulation: nil,
		},
		{
			name: "ht with short gi",
			in:   HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 6, NSS: 2}, HTMCS: 14, ShortGI: true},
			wantAttrs: []netlink.Attribute{
				{Type: unix.NL80211_RATE_INFO_MCS, Data: []byte{14}},
				{Type: unix.NL80211_RATE_INFO_SHORT_GI},
			},
			wantType:       RateModulationInfoTypeHT,
			wantModulation: HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 6, NSS: 2}, HTMCS: 14, ShortGI: true},
		},
		{
			name: "vht without short gi",
			in:   VHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 3, NSS: 1}, ShortGI: false},
			wantAttrs: []netlink.Attribute{
				{Type: unix.NL80211_RATE_INFO_VHT_MCS, Data: []byte{3}},
				{Type: unix.NL80211_RATE_INFO_VHT_NSS, Data: []byte{1}},
			},
			wantType:       RateModulationInfoTypeVHT,
			wantModulation: VHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 3, NSS: 1}, ShortGI: false},
		},
		{
			name: "he",
			in:   HEModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 2, NSS: 1}, GI: 1, DCM: 2, RUAlloc: 3},
			wantAttrs: []netlink.Attribute{
				{Type: unix.NL80211_RATE_INFO_HE_MCS, Data: []byte{2}},
				{Type: unix.NL80211_RATE_INFO_HE_NSS, Data: []byte{1}},
				{Type: unix.NL80211_RATE_INFO_HE_GI, Data: []byte{1}},
				{Type: unix.NL80211_RATE_INFO_HE_DCM, Data: []byte{2}},
				{Type: unix.NL80211_RATE_INFO_HE_RU_ALLOC, Data: []byte{3}},
			},
			wantType:       RateModulationInfoTypeHE,
			wantModulation: HEModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 2, NSS: 1}, GI: 1, DCM: 2, RUAlloc: 3},
		},
		{
			name: "eht",
			in:   EHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 5, NSS: 2}, GI: 22, RUAlloc: 33},
			wantAttrs: []netlink.Attribute{
				{Type: unix.NL80211_RATE_INFO_EHT_MCS, Data: []byte{5}},
				{Type: unix.NL80211_RATE_INFO_EHT_NSS, Data: []byte{2}},
				{Type: unix.NL80211_RATE_INFO_EHT_GI, Data: []byte{22}},
				{Type: unix.NL80211_RATE_INFO_EHT_RU_ALLOC, Data: []byte{33}},
			},
			wantType:       RateModulationInfoTypeEHT,
			wantModulation: EHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: 5, NSS: 2}, GI: 22, RUAlloc: 33},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := modulationAttributes(tt.in)
			if diff := cmp.Diff(tt.wantAttrs, attrs); diff != "" {
				t.Fatalf("unexpected modulation attributes (-want +got):\n%s", diff)
			}

			// Round-trip the generated attributes through the production
			// parser to make sure parseRateInfo actually decodes them back
			// into the expected modulation info, rather than only checking
			// that our own test-fixture marshaling code does what it says.
			got, err := parseRateInfo(mustMarshalAttributes(attrs))
			if err != nil {
				t.Fatalf("failed to parse rate info: %v", err)
			}

			if got.ModulationType != tt.wantType {
				t.Errorf("unexpected modulation type: got %v, want %v", got.ModulationType, tt.wantType)
			}

			if diff := cmp.Diff(tt.wantModulation, got.Modulation); diff != "" {
				t.Errorf("unexpected parsed modulation (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *StationInfo) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		// TODO(mdlayher): return more attributes for validation?
		{
			Type: unix.NL80211_ATTR_MAC,
			Data: s.HardwareAddr,
		},
		{
			Type: unix.NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(s.InterfaceIndex)),
		},
		{
			Type: unix.NL80211_ATTR_STA_INFO,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: unix.NL80211_STA_INFO_CONNECTED_TIME, Data: nlenc.Uint32Bytes(uint32(s.Connected.Seconds()))},
				{Type: unix.NL80211_STA_INFO_INACTIVE_TIME, Data: nlenc.Uint32Bytes(uint32(s.Inactive.Seconds() * 1000))},
				{Type: unix.NL80211_STA_INFO_RX_BYTES, Data: nlenc.Uint32Bytes(uint32(s.ReceivedBytes))},
				{Type: unix.NL80211_STA_INFO_RX_BYTES64, Data: nlenc.Uint64Bytes(uint64(s.ReceivedBytes))},
				{Type: unix.NL80211_STA_INFO_TX_BYTES, Data: nlenc.Uint32Bytes(uint32(s.TransmittedBytes))},
				{Type: unix.NL80211_STA_INFO_TX_BYTES64, Data: nlenc.Uint64Bytes(uint64(s.TransmittedBytes))},
				{Type: unix.NL80211_STA_INFO_SIGNAL, Data: []byte{byte(int8(s.Signal))}},
				{Type: unix.NL80211_STA_INFO_SIGNAL_AVG, Data: []byte{byte(int8(s.SignalAverage))}},
				{Type: unix.NL80211_STA_INFO_RX_PACKETS, Data: nlenc.Uint32Bytes(uint32(s.ReceivedPackets))},
				{Type: unix.NL80211_STA_INFO_TX_PACKETS, Data: nlenc.Uint32Bytes(uint32(s.TransmittedPackets))},
				{Type: unix.NL80211_STA_INFO_TX_RETRIES, Data: nlenc.Uint32Bytes(uint32(s.TransmitRetries))},
				{Type: unix.NL80211_STA_INFO_TX_FAILED, Data: nlenc.Uint32Bytes(uint32(s.TransmitFailed))},
				{Type: unix.NL80211_STA_INFO_BEACON_LOSS, Data: nlenc.Uint32Bytes(uint32(s.BeaconLoss))},
				{
					Type: unix.NL80211_STA_INFO_RX_BITRATE,
					Data: mustMarshalAttributes(slices.Concat(
						[]netlink.Attribute{
							{Type: unix.NL80211_RATE_INFO_BITRATE, Data: nlenc.Uint16Bytes(uint16(bitrateAttr(s.ReceiveBitrate)))},
							{Type: unix.NL80211_RATE_INFO_BITRATE32, Data: nlenc.Uint32Bytes(bitrateAttr(s.ReceiveBitrate))},
						},
						modulationAttributes(s.ReceiveRateInfo.Modulation),
						channelWithAttributes(s.ReceiveRateInfo.ChannelWidth),
					)),
				},
				{
					Type: unix.NL80211_STA_INFO_TX_BITRATE,
					Data: mustMarshalAttributes(slices.Concat(
						[]netlink.Attribute{
							{Type: unix.NL80211_RATE_INFO_BITRATE, Data: nlenc.Uint16Bytes(uint16(bitrateAttr(s.TransmitBitrate)))},
							{Type: unix.NL80211_RATE_INFO_BITRATE32, Data: nlenc.Uint32Bytes(bitrateAttr(s.TransmitBitrate))},
						},
						modulationAttributes(s.TransmitRateInfo.Modulation),
						channelWithAttributes(s.TransmitRateInfo.ChannelWidth),
					)),
				},
			}),
		},
	}
}

func (s *SurveyInfo) attributes() []netlink.Attribute {
	attributes := []netlink.Attribute{
		{Type: unix.NL80211_SURVEY_INFO_FREQUENCY, Data: nlenc.Uint32Bytes(uint32(s.Frequency))},
		{Type: unix.NL80211_SURVEY_INFO_NOISE, Data: []byte{byte(int8(s.Noise))}},
	}
	if s.InUse {
		attributes = append(attributes, netlink.Attribute{Type: unix.NL80211_SURVEY_INFO_IN_USE})
	}
	attributes = append(attributes, []netlink.Attribute{
		{Type: unix.NL80211_SURVEY_INFO_TIME, Data: nlenc.Uint64Bytes(uint64(s.ChannelTime / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_BUSY, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeBusy / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_EXT_BUSY, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeExtBusy / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_BSS_RX, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeBssRx / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_RX, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeRx / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_TX, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeTx / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_SCAN, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeScan / time.Millisecond))},
	}...)
	return []netlink.Attribute{
		{
			Type: unix.NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(s.InterfaceIndex)),
		},
		{
			Type: unix.NL80211_ATTR_SURVEY_INFO,
			Data: mustMarshalAttributes(attributes),
		},
	}
}

func (d *RegulatoryDomain) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: unix.NL80211_ATTR_REG_ALPHA2,
			Data: nlenc.Bytes(d.Region),
		},
	}
}

func bitrateAttr(bitrate int) uint32 {
	return uint32(bitrate / 100 / 1000)
}

func mustMessages(t *testing.T, command uint8, want any) genltest.Func {
	var as []attributeser

	switch xs := want.(type) {
	case []*Interface:
		for _, x := range xs {
			as = append(as, x)
		}
	case *BSS:
		as = append(as, xs)

	case []*StationInfo:
		for _, x := range xs {
			as = append(as, x)
		}
	case []*SurveyInfo:
		for _, x := range xs {
			as = append(as, x)
		}
	case *RegulatoryDomain:
		as = append(as, xs)

	default:
		t.Fatalf("cannot make messages for type: %T", xs)
	}

	msgs := make([]genetlink.Message, 0, len(as))
	for _, a := range as {
		msgs = append(msgs, genetlink.Message{
			Header: genetlink.Header{
				Command: command,
			},
			Data: mustMarshalAttributes(a.attributes()),
		})
	}

	return func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return msgs, nil
	}
}

func Test_decodeBSSLoad(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name                           string
		args                           args
		wantVersion                    uint16
		wantStationCount               uint16
		wantChannelUtilization         uint8
		wantAvailableAdmissionCapacity uint16
	}{
		{name: "Parse BSS Load Normal", args: args{b: []byte{3, 0, 8, 0x8D, 0x5B}}, wantVersion: 2, wantStationCount: 3, wantChannelUtilization: 8, wantAvailableAdmissionCapacity: 23437},
		{name: "Parse BSS Load Version 1", args: args{b: []byte{9, 0, 8, 0x8D}}, wantVersion: 1, wantStationCount: 9, wantChannelUtilization: 8, wantAvailableAdmissionCapacity: 141},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bssLoad, _ := decodeBSSLoad(tt.args.b)
			gotVersion := bssLoad.Version
			gotStationCount := bssLoad.StationCount
			gotChannelUtilization := bssLoad.ChannelUtilization
			gotAvailableAdmissionCapacity := bssLoad.AvailableAdmissionCapacity
			if uint16(gotVersion) != tt.wantVersion {
				t.Errorf("decodeBSSLoad() gotVersion = %v, want %v", gotVersion, tt.wantVersion)
			}
			if gotStationCount != tt.wantStationCount {
				t.Errorf("decodeBSSLoad() gotStationCount = %v, want %v", gotStationCount, tt.wantStationCount)
			}
			if gotChannelUtilization != tt.wantChannelUtilization {
				t.Errorf("decodeBSSLoad() gotChannelUtilization = %v, want %v", gotChannelUtilization, tt.wantChannelUtilization)
			}
			if gotAvailableAdmissionCapacity != tt.wantAvailableAdmissionCapacity {
				t.Errorf("decodeBSSLoad() gotAvailableAdmissionCapacity = %v, want %v", gotAvailableAdmissionCapacity, tt.wantAvailableAdmissionCapacity)
			}
		})
	}
}

func Test_decodeBSSLoadError(t *testing.T) {
	t.Parallel()
	_, err := decodeBSSLoad([]byte{3, 0, 8})
	if err == nil {
		t.Error("want error on bogus IE with wrong length")
	}
}

func TestLinux_clientSurveryInfoMissingAttributeIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// One message without station info attribute
		return []genetlink.Message{{
			Header: genetlink.Header{
				Command: unix.NL80211_CMD_GET_SURVEY,
			},
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NL80211_ATTR_IFINDEX,
				Data: nlenc.Uint32Bytes(1),
			}}),
		}}, nil
	})

	_, err := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientSurveyInfoNoMessagesIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// No messages about station info at the generic netlink level.
		// Caller will interpret this as no station info.
		return nil, io.EOF
	})

	info, err := c.SurveyInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if err != nil {
		t.Fatalf("undexpected error: %v", err)
	}
	if !reflect.DeepEqual(info, []*SurveyInfo{}) {
		t.Fatalf("expected info to be an empty slice, got %v", info)
	}
}

func TestLinux_clientSurveyInfoOK(t *testing.T) {
	want := []*SurveyInfo{
		{
			InterfaceIndex:     1,
			Frequency:          2412,
			Noise:              -95,
			InUse:              true,
			ChannelTime:        100 * time.Millisecond,
			ChannelTimeBusy:    50 * time.Millisecond,
			ChannelTimeExtBusy: 10 * time.Millisecond,
			ChannelTimeBssRx:   20 * time.Millisecond,
			ChannelTimeRx:      30 * time.Millisecond,
			ChannelTimeTx:      40 * time.Millisecond,
			ChannelTimeScan:    5 * time.Millisecond,
		},
		{
			InterfaceIndex:     1,
			Frequency:          2437,
			Noise:              -90,
			InUse:              false,
			ChannelTime:        200 * time.Millisecond,
			ChannelTimeBusy:    100 * time.Millisecond,
			ChannelTimeExtBusy: 20 * time.Millisecond,
			ChannelTimeBssRx:   40 * time.Millisecond,
			ChannelTimeRx:      60 * time.Millisecond,
			ChannelTimeTx:      80 * time.Millisecond,
			ChannelTimeScan:    10 * time.Millisecond,
		},
	}

	ifi := &Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	}

	const flags = netlink.Request | netlink.Dump

	msgsFn := mustMessages(t, unix.NL80211_CMD_GET_SURVEY, want)

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_SURVEY, flags,
		func(greq genetlink.Message, nreq netlink.Message) ([]genetlink.Message, error) {
			// Also verify that the correct interface attributes are
			// present in the request.
			attrs, err := netlink.UnmarshalAttributes(greq.Data)
			if err != nil {
				t.Fatalf("failed to unmarshal attributes: %v", err)
			}

			if diff := diffNetlinkAttributes(ifi.idAttrs(), attrs); diff != "" {
				t.Fatalf("unexpected request netlink attributes (-want +got):\n%s", diff)
			}

			return msgsFn(greq, nreq)
		},
	))

	got, err := c.SurveyInfo(ifi)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	for i := range want {
		if !reflect.DeepEqual(want[i], got[i]) {
			t.Fatalf("unexpected station info:\n- want: %v\n-  got: %v",
				want[i], got[i])
		}
	}
}

// Test data helpers for decodeRSN tests
func buildRSNIE(parts ...[]byte) []byte {
	var result []byte
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}

var (
	rsnVersion1      = []byte{0x01, 0x00}
	rsnVersion2      = []byte{0x02, 0x00}
	ccmp128Cipher    = []byte{0x00, 0x0F, 0xAC, 0x04}
	tkipCipher       = []byte{0x00, 0x0F, 0xAC, 0x02}
	bipCmac128Cipher = []byte{0x00, 0x0F, 0xAC, 0x06}
	pskAKM           = []byte{0x00, 0x0F, 0xAC, 0x02}
	saeAKM           = []byte{0x00, 0x0F, 0xAC, 0x08}
	dot1xAKM         = []byte{0x00, 0x0F, 0xAC, 0x01}
	oneCipherCount   = []byte{0x01, 0x00}
	twoCipherCount   = []byte{0x02, 0x00}
	zeroCount        = []byte{0x00, 0x00}
	pmfCapable       = []byte{0x80, 0x00}
	pmfRequired      = []byte{0xC0, 0x00}
	pmkid16Bytes     = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
)

// Test valid RSN cases
func Test_decodeRSN_ValidCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *RSNInfo
	}{
		{
			name:  "minimal valid RSN",
			input: buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{},
			},
		},
		{
			name:  "complete RSN with AKMs and capabilities",
			input: buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, oneCipherCount, pskAKM, pmfCapable),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSNAkmPSK},
				Capabilities:    0x0080,
			},
		},
		{
			name:  "multiple pairwise ciphers and AKMs",
			input: buildRSNIE(rsnVersion1, tkipCipher, twoCipherCount, tkipCipher, ccmp128Cipher, twoCipherCount, dot1xAKM, pskAKM),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherTKIP,
				PairwiseCiphers: []RSNCipher{RSNCipherTKIP, RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSNAkm8021X, RSNAkmPSK},
			},
		},
		{
			name:  "with group management cipher (WPA3/802.11w)",
			input: buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, oneCipherCount, saeAKM, pmfRequired, zeroCount, bipCmac128Cipher),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSNAkmSAE},
				Capabilities:    0x00C0,
				GroupMgmtCipher: RSNCipherBIPCMAC128,
			},
		},
		{
			name:  "with PMKID list",
			input: buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, oneCipherCount, pskAKM, zeroCount, oneCipherCount, pmkid16Bytes),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSNAkmPSK},
			},
		},
		{
			name:  "version 2 (should be accepted)",
			input: buildRSNIE(rsnVersion2, ccmp128Cipher, oneCipherCount, ccmp128Cipher),
			expected: &RSNInfo{
				Version:         2,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{},
			},
		},
		{
			name:  "unknown cipher and AKM values",
			input: buildRSNIE(rsnVersion1, []byte{0xFF, 0xFF, 0xFF, 0xFF}, oneCipherCount, []byte{0xAA, 0xBB, 0xCC, 0xDD}, oneCipherCount, []byte{0x11, 0x22, 0x33, 0x44}),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipher(0xFFFFFFFF),
				PairwiseCiphers: []RSNCipher{RSNCipher(0xAABBCCDD)},
				AKMs:            []RSNAKM{RSNAKM(0x11223344)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidRSN(t, tt.input, tt.expected)
		})
	}
}

// Test RSN error cases
func Test_decodeRSN_ErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *RSNInfo
		errMsg   string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: &RSNInfo{},
			errMsg:   "RSN IE parsing error: IE too short",
		},
		{
			name:     "too short - less than minimum 8 bytes",
			input:    []byte{0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01},
			expected: &RSNInfo{},
			errMsg:   "RSN IE parsing error: IE too short",
		},
		{
			name:     "version 0 (invalid)",
			input:    []byte{0x00, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00},
			expected: &RSNInfo{Version: 0},
			errMsg:   "RSN IE parsing error: invalid version 0",
		},
		{
			name:     "truncated before pairwise count",
			input:    buildRSNIE(rsnVersion1, ccmp128Cipher),
			expected: &RSNInfo{},
			errMsg:   "RSN IE parsing error: IE too short",
		},
		{
			name:     "IE data exceeds maximum size",
			input:    make([]byte, 254),
			expected: &RSNInfo{},
			errMsg:   "RSN IE parsing error: data exceeds maximum size of 253 octets",
		},
	}

	// Initialize the oversized test case
	tests[4].input[0] = 0x01 // version

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRSNError(t, tt.input, tt.expected, tt.errMsg)
		})
	}
}

// Test RSN truncation errors (streamlined)
func Test_decodeRSN_TruncationErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *RSNInfo
		errMsg   string
	}{
		{
			name:     "truncated in pairwise list",
			input:    buildRSNIE(rsnVersion1, ccmp128Cipher, twoCipherCount, ccmp128Cipher),
			expected: &RSNInfo{Version: 1, GroupCipher: RSNCipherCCMP128},
			errMsg:   "RSN IE parsing error: truncated in pairwise list",
		},
		{
			name:     "truncated in AKM list",
			input:    buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, twoCipherCount, dot1xAKM),
			expected: &RSNInfo{Version: 1, GroupCipher: RSNCipherCCMP128, PairwiseCiphers: []RSNCipher{RSNCipherCCMP128}},
			errMsg:   "RSN IE parsing error: truncated in AKM list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRSNError(t, tt.input, tt.expected, tt.errMsg)
		})
	}
}

// Test RSN count validation and edge cases
func Test_decodeRSN_CountValidation(t *testing.T) {
	t.Run("count errors", func(t *testing.T) {
		tests := []struct {
			name     string
			input    []byte
			expected *RSNInfo
			errMsg   string
		}{
			{
				name:     "pairwise cipher count too large",
				input:    buildRSNIE(rsnVersion1, ccmp128Cipher, []byte{0xFF, 0x00}),
				expected: &RSNInfo{Version: 1, GroupCipher: RSNCipherCCMP128},
				errMsg:   "RSN IE parsing error: pairwise cipher count too large",
			},
			{
				name:     "AKM count too large",
				input:    buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, []byte{0xFF, 0x00}),
				expected: &RSNInfo{Version: 1, GroupCipher: RSNCipherCCMP128, PairwiseCiphers: []RSNCipher{RSNCipherCCMP128}},
				errMsg:   "RSN IE parsing error: AKM count too large",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assertRSNError(t, tt.input, tt.expected, tt.errMsg)
			})
		}
	})

	t.Run("zero counts (valid)", func(t *testing.T) {
		tests := []struct {
			name  string
			input []byte
		}{
			{"zero pairwise cipher count", buildRSNIE(rsnVersion1, ccmp128Cipher, zeroCount)},
			{"zero AKM count", buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, zeroCount)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := decodeRSN(tt.input)
				if err != nil {
					t.Errorf("decodeRSN() failed: %v", err)
				}
				if got.Version != 1 {
					t.Errorf("decodeRSN() version = %v, want 1", got.Version)
				}
			})
		}
	})
}

// compareRSNCipherSlices compares two RSNCipher slices, treating nil and empty slices as equal
func compareRSNCipherSlices(a, b []RSNCipher) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// compareRSNAKMSlices compares two RSNAKM slices, treating nil and empty slices as equal
func compareRSNAKMSlices(a, b []RSNAKM) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// Helper assertion functions for RSN tests
func assertValidRSN(t *testing.T, input []byte, expected *RSNInfo) {
	t.Helper()
	got, err := decodeRSN(input)
	if err != nil {
		t.Errorf("decodeRSN() unexpected error = %v", err)
		return
	}

	// Compare individual fields
	if got.Version != expected.Version {
		t.Errorf("decodeRSN() version = %v, want %v", got.Version, expected.Version)
	}
	if got.GroupCipher != expected.GroupCipher {
		t.Errorf("decodeRSN() group cipher = %v, want %v", got.GroupCipher, expected.GroupCipher)
	}
	if !compareRSNCipherSlices(got.PairwiseCiphers, expected.PairwiseCiphers) {
		t.Errorf("decodeRSN() pairwise ciphers = %v, want %v", got.PairwiseCiphers, expected.PairwiseCiphers)
	}
	if !compareRSNAKMSlices(got.AKMs, expected.AKMs) {
		t.Errorf("decodeRSN() AKMs = %v, want %v", got.AKMs, expected.AKMs)
	}
	if got.Capabilities != expected.Capabilities {
		t.Errorf("decodeRSN() capabilities = %v, want %v", got.Capabilities, expected.Capabilities)
	}
	if got.GroupMgmtCipher != expected.GroupMgmtCipher {
		t.Errorf("decodeRSN() group mgmt cipher = %v, want %v", got.GroupMgmtCipher, expected.GroupMgmtCipher)
	}
}

func assertRSNError(t *testing.T, input []byte, expected *RSNInfo, errMsg string) {
	t.Helper()
	got, err := decodeRSN(input)
	if err == nil {
		t.Errorf("decodeRSN() expected error but got none")
		return
	}
	if errMsg != "" && err.Error() != errMsg {
		t.Errorf("decodeRSN() error = %v, want %v", err.Error(), errMsg)
	}

	// For error cases, check partial parsing results
	if got.Version != expected.Version {
		t.Errorf("decodeRSN() version = %v, want %v", got.Version, expected.Version)
	}
	if got.GroupCipher != expected.GroupCipher {
		t.Errorf("decodeRSN() group cipher = %v, want %v", got.GroupCipher, expected.GroupCipher)
	}
}

func TestLinux_GetRegulatoryDomain_NoMessages(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// No messages
		return nil, io.EOF
	})

	_, err := c.GetRegulatoryDomain()
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_GetRegulatoryDomain_OK(t *testing.T) {
	want := &RegulatoryDomain{
		Region: "GB",
	}

	const flags = netlink.Request

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_REG, flags,
		mustMessages(t, unix.NL80211_CMD_GET_REG, want),
	))

	got, err := c.GetRegulatoryDomain()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected region (-want +got):\n%s", diff)
	}
}

// The devices below support two spatial streams: MCS 0-11 for HE, and every
// EHT MCS range.
var (
	heMCS11NSS2 = [8]int{11, 11, -1, -1, -1, -1, -1, -1}

	ehtMCS2NSS = []EHTMCSNSS{
		{MinMCS: 0, MaxMCS: 9, RxMaxNSS: 2, TxMaxNSS: 2},
		{MinMCS: 10, MaxMCS: 11, RxMaxNSS: 2, TxMaxNSS: 2},
		{MinMCS: 12, MaxMCS: 13, RxMaxNSS: 2, TxMaxNSS: 2},
	}
)

// Capability data captured from a MediaTek MT7925 (802.11be) device, for the
// station interface type of its 2.4GHz and 6GHz bands.
var (
	mt7925HECapMAC = []byte{0x01, 0x08, 0x00, 0x1a, 0x40, 0x00}

	// The kernel reports the PPE thresholds as a fixed-size buffer, so most
	// of this is padding.
	mt7925HECapPPE = []byte{
		0x19, 0x1c, 0xc7, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// The HE-MCS maps for 80MHz, 160MHz and 80+80MHz channels: the device
	// supports MCS 0-11 with one and two spatial streams.
	mt7925HECapMCSSet = []byte{
		0xfa, 0xff, 0xfa, 0xff,
		0xfa, 0xff, 0xfa, 0xff,
		0x00, 0x00, 0x00, 0x00,
	}

	// 40MHz in the 2.4GHz band, versus 40MHz, 80MHz and 160MHz in the 5GHz
	// and 6GHz bands.
	mt7925HECapPHY24GHz = []byte{
		0x22, 0x70, 0xce, 0x12, 0x6d, 0xc0,
		0xb3, 0x06, 0x4e, 0x3f, 0x00,
	}
	mt7925HECapPHY6GHz = []byte{
		0x4c, 0x70, 0xce, 0x12, 0x6d, 0xc0,
		0xb3, 0x06, 0x4e, 0x3f, 0x00,
	}

	mt7925EHTCapMAC = []byte{0x03, 0x00}
	mt7925EHTCapPHY = []byte{
		0xe8, 0x04, 0x09, 0xfe, 0x10,
		0x61, 0x0c, 0x36, 0x00,
	}
)

func TestLinux_parseBandIftypeData(t *testing.T) {
	tests := []struct {
		name    string
		attrs   []netlink.Attribute
		he      []HECapabilities
		eht     []EHTCapabilities
		wantErr error
	}{
		{
			name: "no capabilities",
			attrs: []netlink.Attribute{
				{
					Type: unix.NL80211_BAND_IFTYPE_ATTR_IFTYPES,
					Data: mustMarshalAttributes([]netlink.Attribute{
						{Type: uint16(InterfaceTypeStation)},
					}),
				},
			},
		},
		{
			name: "HE only",
			attrs: []netlink.Attribute{
				{
					Type: unix.NL80211_BAND_IFTYPE_ATTR_IFTYPES,
					Data: mustMarshalAttributes([]netlink.Attribute{
						{Type: uint16(InterfaceTypeStation)},
						{Type: uint16(InterfaceTypeAP)},
					}),
				},
				{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, Data: mt7925HECapMAC},
				{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, Data: mt7925HECapPHY24GHz},
			},
			he: []HECapabilities{{
				InterfaceTypes:                     []InterfaceType{InterfaceTypeStation, InterfaceTypeAP},
				HTCHE:                              true,
				TriggerFrameMACPaddingDuration:     16,
				OMControl:                          true,
				MaxAMPDULengthExponentExt:          3,
				AMSDUInAMPDU:                       true,
				Support40MHzIn2GHz:                 true,
				Support242ToneRUIn2GHz:             true,
				DeviceClassA:                       true,
				LDPCCodingInPayload:                true,
				HESUPPDU1xHELTFAnd08usGI:           true,
				NDP4xHELTFAnd32usGI:                true,
				STBCTx80MHz:                        true,
				STBCRx80MHz:                        true,
				FullBandwidthULMUMIMO:              true,
				PartialBandwidthULMUMIMO:           true,
				DCMMaxConstellationTx:              2,
				DCMMaxConstellationRx:              2,
				SUBeamformee:                       true,
				BeamformeeSTS80MHz:                 3,
				BeamformeeSTSAbove80MHz:            3,
				NG16SUFeedback:                     true,
				NG16MUFeedback:                     true,
				Codebook42SUFeedback:               true,
				Codebook75MUFeedback:               true,
				TriggeredCQIFeedback:               true,
				PartialBandwidthExtendedRange:      true,
				PPEThresholdsPresent:               true,
				PowerBoostFactor:                   true,
				HESUMUPPDU4xHELTFAnd08usGI:         true,
				Support20MHzIn40MHzHEPPDUIn2GHz:    true,
				Support20MHzIn160MHzHEPPDU:         true,
				Support80MHzIn160MHzHEPPDU:         true,
				DCMMaxRU:                           1,
				LongerThan16HESIGBOFDMSymbols:      true,
				NonTriggeredCQIFeedback:            true,
				Tx1024QAMLess242ToneRU:             true,
				Rx1024QAMLess242ToneRU:             true,
				RxFullBWSUUsingMUCompressedSIGB:    true,
				RxFullBWSUUsingMUNonCompressedSIGB: true,
			}},
		},
		{
			name:  "2.4GHz station",
			attrs: mt7925IftypeAttrs(mt7925HECapPHY24GHz, []byte{0x22, 0x22, 0x22}, nil),
			// In the 2.4GHz band a device which supports 40MHz channels
			// reports a single EHT-MCS map.
			he:  []HECapabilities{mt7925HECapabilities(mt7925HECapPHY24GHz, ChannelWidth80)},
			eht: []EHTCapabilities{mt7925EHTCapabilities([]byte{0x22, 0x22, 0x22}, ChannelWidth80)},
		},
		{
			name: "6GHz station",
			attrs: mt7925IftypeAttrs(
				mt7925HECapPHY6GHz,
				[]byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
				[]byte{0xba, 0x30},
			),
			// 160MHz support adds a second map to both the HE-MCS and
			// the EHT-MCS sets.
			he: []HECapabilities{func() HECapabilities {
				he := mt7925HECapabilities(mt7925HECapPHY6GHz, ChannelWidth80, ChannelWidth160)
				he.HE6GHzCapabilities = &HE6GHzCapabilities{
					MinMPDUStartSpacing: 500 * time.Nanosecond,
					MaxRxAMPDULength:    1048575,
					MaxMPDULength:       11454,
					RXAntennaPattern:    true,
					TXAntennaPattern:    true,
				}
				return he
			}()},
			eht: []EHTCapabilities{mt7925EHTCapabilities(
				[]byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
				ChannelWidth80, ChannelWidth160,
			)},
		},
		{
			name: "6GHz AP, 320MHz capable",
			attrs: ath12kIftypeAttrs(
				InterfaceTypeAP,
				ath12kHECapMACAP, ath12kHECapPHYAP,
				ath12kEHTCapMAC, ath12kEHTCapPHYAP,
			),
			he: []HECapabilities{{
				InterfaceTypes:                          []InterfaceType{InterfaceTypeAP},
				HTCHE:                                   true,
				TWTResponder:                            true,
				DynamicFragmentation:                    1,
				BSR:                                     true,
				BroadcastTWT:                            true,
				OMControl:                               true,
				MaxAMPDULengthExponentExt:               3,
				RxControlFrameToMultiBSS:                true,
				AMSDUInAMPDU:                            true,
				UL2x996ToneRU:                           true,
				OMControlULMUDataDisableRx:              true,
				Support40MHz80MHzIn5GHz:                 true,
				Support160MHzIn5GHz:                     true,
				PuncturedPreambleRx:                     3,
				LDPCCodingInPayload:                     true,
				HESUPPDU1xHELTFAnd08usGI:                true,
				FullBandwidthULMUMIMO:                   true,
				DCMMaxConstellationRx:                   1,
				SUBeamformer:                            true,
				SUBeamformee:                            true,
				MUBeamformer:                            true,
				BeamformeeSTS80MHz:                      7,
				BeamformeeSTSAbove80MHz:                 7,
				SoundingDimensions80MHz:                 1,
				SoundingDimensionsAbove80MHz:            3,
				NG16SUFeedback:                          true,
				NG16MUFeedback:                          true,
				Codebook42SUFeedback:                    true,
				Codebook75MUFeedback:                    true,
				TriggeredSUBeamformingFeedback:          true,
				TriggeredMUBeamformingPartialBWFeedback: true,
				TriggeredCQIFeedback:                    true,
				PPEThresholdsPresent:                    true,
				HESUMUPPDU4xHELTFAnd08usGI:              true,
				MaxNc:                                   3,
				HEERSUPPDU4xHELTFAnd08usGI:              true,
				HEERSUPPDU1xHELTFAnd08usGI:              true,
				NonTriggeredCQIFeedback:                 true,
				Tx1024QAMLess242ToneRU:                  true,
				Rx1024QAMLess242ToneRU:                  true,
				SupportedMCSSets: []HEMCSNSSSet{
					{Width: ChannelWidth80, RxHighestMCS: heMCS11NSS2, TxHighestMCS: heMCS11NSS2},
					{Width: ChannelWidth160, RxHighestMCS: heMCS11NSS2, TxHighestMCS: heMCS11NSS2},
				},
				SupportedMCS:  ath12kHECapMCSSet,
				PPEThresholds: ath12kHECapPPE,
				HE6GHzCapabilities: &HE6GHzCapabilities{
					MaxRxAMPDULength: 1048575,
					MaxMPDULength:    11454,
					SMPowerSave:      1,
					RXAntennaPattern: true,
					TXAntennaPattern: true,
				},
			}},
			eht: []EHTCapabilities{{
				InterfaceTypes:                          []InterfaceType{InterfaceTypeAP},
				EPCSPriorityAccess:                      true,
				OMControl:                               true,
				TriggeredTXOPSharingMode1:               true,
				RestrictedTWT:                           true,
				SCSTrafficDescription:                   true,
				MaxMPDULength:                           3895,
				Support320MHzIn6GHz:                     true,
				SUBeamformer:                            true,
				SUBeamformee:                            true,
				BeamformeeSS80MHz:                       7,
				BeamformeeSS160MHz:                      7,
				BeamformeeSS320MHz:                      7,
				SoundingDimensions80MHz:                 3,
				SoundingDimensions160MHz:                3,
				SoundingDimensions320MHz:                3,
				TriggeredSUBeamformingFeedback:          true,
				TriggeredMUBeamformingPartialBWFeedback: true,
				TriggeredCQIFeedback:                    true,
				EHTMUPPDU4xEHTLTFAnd08usGI:              true,
				MaxNc:                                   1,
				NonTriggeredCQIFeedback:                 true,
				RxLess242ToneRU:                         true,
				CommonNominalPacketPadding:              20,
				MaxSupportedEHTLTFs:                     1,
				EHTDupIn6GHz:                            true,
				NonOFDMAULMUMIMO80MHz:                   true,
				NonOFDMAULMUMIMO160MHz:                  true,
				NonOFDMAULMUMIMO320MHz:                  true,
				MUBeamformer80MHz:                       true,
				MUBeamformer160MHz:                      true,
				MUBeamformer320MHz:                      true,
				SupportedMCSSets: []EHTMCSNSSSet{
					{Width: ChannelWidth80, MCSRanges: ehtMCS2NSS},
					{Width: ChannelWidth160, MCSRanges: ehtMCS2NSS},
					{Width: ChannelWidth320, MCSRanges: ehtMCS2NSS},
				},
				SupportedMCS: ath12kEHTCapMCSSet,
			}},
		},
		{
			// A device which supports no channel width beyond
			// 20MHz reports the shorter EHT-MCS map, and its
			// mandatory first HE-MCS map describes 20MHz.
			name: "20MHz-only station",
			attrs: narrowIftypeAttrs(
				InterfaceTypeStation,
				[]byte{0x22, 0x22, 0x22, 0x11},
			),
			he: []HECapabilities{{
				InterfaceTypes: []InterfaceType{InterfaceTypeStation},
				SupportedMCSSets: []HEMCSNSSSet{{
					Width:        ChannelWidth20,
					RxHighestMCS: heMCS11NSS2,
					TxHighestMCS: heMCS11NSS2,
				}},
				SupportedMCS: mt7925HECapMCSSet,
			}},
			eht: []EHTCapabilities{{
				InterfaceTypes: []InterfaceType{InterfaceTypeStation},
				MaxMPDULength:  3895,
				SupportedMCSSets: []EHTMCSNSSSet{{
					Width: ChannelWidth20,
					MCSRanges: []EHTMCSNSS{
						{MinMCS: 0, MaxMCS: 7, RxMaxNSS: 2, TxMaxNSS: 2},
						{MinMCS: 8, MaxMCS: 9, RxMaxNSS: 2, TxMaxNSS: 2},
						{MinMCS: 10, MaxMCS: 11, RxMaxNSS: 2, TxMaxNSS: 2},
						{MinMCS: 12, MaxMCS: 13, RxMaxNSS: 1, TxMaxNSS: 1},
					},
				}},
				SupportedMCS: []byte{0x22, 0x22, 0x22, 0x11},
			}},
		},
		{
			// An access point reports the wider map even when it
			// advertises no channel width beyond 20MHz.
			name:  "20MHz-only AP",
			attrs: narrowIftypeAttrs(InterfaceTypeAP, []byte{0x22, 0x22, 0x22}),
			he: []HECapabilities{{
				InterfaceTypes: []InterfaceType{InterfaceTypeAP},
				SupportedMCSSets: []HEMCSNSSSet{{
					Width:        ChannelWidth20,
					RxHighestMCS: heMCS11NSS2,
					TxHighestMCS: heMCS11NSS2,
				}},
				SupportedMCS: mt7925HECapMCSSet,
			}},
			eht: []EHTCapabilities{{
				InterfaceTypes:   []InterfaceType{InterfaceTypeAP},
				MaxMPDULength:    3895,
				SupportedMCSSets: []EHTMCSNSSSet{{Width: ChannelWidth80, MCSRanges: ehtMCS2NSS}},
				SupportedMCS:     []byte{0x22, 0x22, 0x22},
			}},
		},
		{
			name: "truncated HE PHY capabilities",
			attrs: []netlink.Attribute{
				{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, Data: mt7925HECapPHY24GHz[:10]},
			},
			wantErr: errInvalidHECapabilities,
		},
		{
			name: "truncated HE 6GHz capabilities",
			attrs: []netlink.Attribute{
				{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, Data: mt7925HECapMAC},
				{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA, Data: []byte{0xba}},
			},
			wantErr: errInvalidHECapabilities,
		},
		{
			name: "truncated EHT MAC capabilities",
			attrs: []netlink.Attribute{
				{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, Data: mt7925EHTCapMAC[:1]},
			},
			wantErr: errInvalidEHTCapabilities,
		},
		{
			name: "truncated HE MAC capabilities",
			attrs: []netlink.Attribute{
				{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, Data: mt7925HECapMAC[:5]},
			},
			wantErr: errInvalidHECapabilities,
		},
		{
			name: "truncated EHT PHY capabilities",
			attrs: []netlink.Attribute{
				{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, Data: mt7925EHTCapPHY[:8]},
			},
			wantErr: errInvalidEHTCapabilities,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The kernel nests the attributes of each interface type
			// within an outer attribute indexed from one.
			b := mustMarshalAttributes([]netlink.Attribute{{
				Type: 1,
				Data: mustMarshalAttributes(tt.attrs),
			}})

			he, eht, err := parseBandIftypeData(b)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("unexpected error: got %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tt.he, he); diff != "" {
				t.Errorf("unexpected HE capabilities (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.eht, eht); diff != "" {
				t.Errorf("unexpected EHT capabilities (-want +got):\n%s", diff)
			}
		})
	}
}

// mt7925IftypeAttrs builds the attributes the kernel reports for the station
// interface type of one band of an MT7925 device.
func mt7925IftypeAttrs(hePHYCap, ehtMCSSet, he6GHzCapa []byte) []netlink.Attribute {
	attrs := []netlink.Attribute{
		{
			Type: unix.NL80211_BAND_IFTYPE_ATTR_IFTYPES,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: uint16(InterfaceTypeStation)},
			}),
		},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, Data: mt7925HECapMAC},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, Data: hePHYCap},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET, Data: mt7925HECapMCSSet},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE, Data: mt7925HECapPPE},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, Data: mt7925EHTCapMAC},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, Data: mt7925EHTCapPHY},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET, Data: ehtMCSSet},
	}

	if he6GHzCapa != nil {
		attrs = append(attrs, netlink.Attribute{
			Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA,
			Data: he6GHzCapa,
		})
	}

	return attrs
}

// mt7925HECapabilities returns the HE capabilities an MT7925 device advertises
// for the station interface type, with one HE-MCS set per channel width in
// widths.
func mt7925HECapabilities(hePHYCap []byte, widths ...ChannelWidth) HECapabilities {
	// The device supports MCS 0-11 with one and two spatial streams, at
	// every channel width it supports.
	sets := make([]HEMCSNSSSet, 0, len(widths))
	for _, w := range widths {
		sets = append(sets, HEMCSNSSSet{
			Width:        w,
			RxHighestMCS: heMCS11NSS2,
			TxHighestMCS: heMCS11NSS2,
		})
	}

	return HECapabilities{
		InterfaceTypes:                     []InterfaceType{InterfaceTypeStation},
		HTCHE:                              true,
		TriggerFrameMACPaddingDuration:     16,
		OMControl:                          true,
		MaxAMPDULengthExponentExt:          3,
		AMSDUInAMPDU:                       true,
		Support40MHzIn2GHz:                 hePHYCap[0]&(1<<1) != 0,
		Support40MHz80MHzIn5GHz:            hePHYCap[0]&(1<<2) != 0,
		Support160MHzIn5GHz:                hePHYCap[0]&(1<<3) != 0,
		Support242ToneRUIn2GHz:             hePHYCap[0]&(1<<5) != 0,
		Support242ToneRUIn5GHz:             hePHYCap[0]&(1<<6) != 0,
		DeviceClassA:                       true,
		LDPCCodingInPayload:                true,
		HESUPPDU1xHELTFAnd08usGI:           true,
		NDP4xHELTFAnd32usGI:                true,
		STBCTx80MHz:                        true,
		STBCRx80MHz:                        true,
		FullBandwidthULMUMIMO:              true,
		PartialBandwidthULMUMIMO:           true,
		DCMMaxConstellationTx:              2,
		DCMMaxConstellationRx:              2,
		SUBeamformee:                       true,
		BeamformeeSTS80MHz:                 3,
		BeamformeeSTSAbove80MHz:            3,
		NG16SUFeedback:                     true,
		NG16MUFeedback:                     true,
		Codebook42SUFeedback:               true,
		Codebook75MUFeedback:               true,
		TriggeredCQIFeedback:               true,
		PartialBandwidthExtendedRange:      true,
		PPEThresholdsPresent:               true,
		PowerBoostFactor:                   true,
		HESUMUPPDU4xHELTFAnd08usGI:         true,
		Support20MHzIn40MHzHEPPDUIn2GHz:    true,
		Support20MHzIn160MHzHEPPDU:         true,
		Support80MHzIn160MHzHEPPDU:         true,
		DCMMaxRU:                           1,
		LongerThan16HESIGBOFDMSymbols:      true,
		NonTriggeredCQIFeedback:            true,
		Tx1024QAMLess242ToneRU:             true,
		Rx1024QAMLess242ToneRU:             true,
		RxFullBWSUUsingMUCompressedSIGB:    true,
		RxFullBWSUUsingMUNonCompressedSIGB: true,
		SupportedMCSSets:                   sets,
		SupportedMCS:                       mt7925HECapMCSSet,
		PPEThresholds:                      mt7925HECapPPE,
	}
}

// mt7925EHTCapabilities returns the EHT capabilities an MT7925 device
// advertises for the station interface type, with one EHT-MCS set per channel
// width in widths.
func mt7925EHTCapabilities(ehtMCSSet []byte, widths ...ChannelWidth) EHTCapabilities {
	// The device supports two spatial streams for every MCS range, at every
	// channel width it supports.
	sets := make([]EHTMCSNSSSet, 0, len(widths))
	for _, w := range widths {
		sets = append(sets, EHTMCSNSSSet{
			Width:     w,
			MCSRanges: ehtMCS2NSS,
		})
	}

	return EHTCapabilities{
		InterfaceTypes:                          []InterfaceType{InterfaceTypeStation},
		EPCSPriorityAccess:                      true,
		OMControl:                               true,
		MaxMPDULength:                           3895,
		NDP4xEHTLTFAnd32usGI:                    true,
		SUBeamformer:                            true,
		SUBeamformee:                            true,
		BeamformeeSS80MHz:                       1,
		BeamformeeSS160MHz:                      1,
		SoundingDimensions80MHz:                 1,
		SoundingDimensions160MHz:                1,
		NG16SUFeedback:                          true,
		NG16MUFeedback:                          true,
		Codebook42SUFeedback:                    true,
		Codebook75MUFeedback:                    true,
		TriggeredSUBeamformingFeedback:          true,
		TriggeredMUBeamformingPartialBWFeedback: true,
		TriggeredCQIFeedback:                    true,
		MaxNc:                                   1,
		NonTriggeredCQIFeedback:                 true,
		CommonNominalPacketPadding:              16,
		MaxSupportedEHTLTFs:                     17,
		MCS15Support:                            1,
		NonOFDMAULMUMIMO80MHz:                   true,
		NonOFDMAULMUMIMO160MHz:                  true,
		MUBeamformer80MHz:                       true,
		MUBeamformer160MHz:                      true,
		SupportedMCSSets:                        sets,
		SupportedMCS:                            ehtMCSSet,
	}
}

// Capability data captured from an 8devices Kiwi-DVK (ath12k, 802.11be), for
// the three interface types of its 6GHz band.  Unlike the MT7925 above, this device
// supports 320MHz channels, so its Supported EHT-MCS And NSS Set holds three
// maps rather than one.
var (
	ath12kHECapMACStation = []byte{0x0b, 0x00, 0x18, 0x9a, 0x40, 0x18}
	ath12kHECapMACAP      = []byte{0x0d, 0x00, 0x18, 0x9a, 0x40, 0x18}
	ath12kHECapMACMesh    = []byte{0x09, 0x00, 0x08, 0x8a, 0x40, 0x10}

	ath12kHECapPHYStation = []byte{
		0x0c, 0x63, 0x40, 0x89, 0xff, 0xd9,
		0x9f, 0x1c, 0x11, 0x0e, 0x00,
	}
	ath12kHECapPHYAP = []byte{
		0x0c, 0x63, 0x40, 0x88, 0xff, 0xd9,
		0x9f, 0x1c, 0x11, 0x0e, 0x00,
	}
	ath12kHECapPHYMesh = []byte{
		0x0c, 0x63, 0x00, 0x80, 0xfd, 0x59,
		0x85, 0x1c, 0x10, 0x00, 0x00,
	}

	ath12kHECapMCSSet = []byte{
		0xfa, 0xff, 0xfa, 0xff,
		0xfa, 0xff, 0xfa, 0xff,
		0x00, 0x00, 0x00, 0x00,
	}
	ath12kHECapPPE = []byte{
		0x79, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	ath12kEHTCapMAC     = []byte{0x37, 0x00}
	ath12kEHTCapMACMesh = []byte{0x36, 0x00}

	ath12kEHTCapPHYStation = []byte{
		0xe2, 0xff, 0xdb, 0xe0, 0x18,
		0x77, 0x80, 0x00, 0x00,
	}
	ath12kEHTCapPHYAP = []byte{
		0xe2, 0xff, 0xdb, 0xe0, 0x18,
		0x75, 0x80, 0x7e, 0x00,
	}
	ath12kEHTCapPHYMesh = []byte{
		0xe2, 0xff, 0xdb, 0x20, 0x10,
		0x30, 0x80, 0x00, 0x00,
	}

	// Three maps: 80MHz and below, 160MHz and 320MHz.
	ath12kEHTCapMCSSet = []byte{
		0x22, 0x22, 0x22,
		0x22, 0x22, 0x22,
		0x22, 0x22, 0x22,
	}

	ath12kHE6GHzCapa = []byte{0xb8, 0x32}
)

// ath12kIftypeAttrs builds the attributes the kernel reports for one interface
// type of the 6GHz band of an ath12k device.
func ath12kIftypeAttrs(iftype InterfaceType, heMAC, hePHY, ehtMAC, ehtPHY []byte) []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: unix.NL80211_BAND_IFTYPE_ATTR_IFTYPES,
			Data: mustMarshalAttributes([]netlink.Attribute{{Type: uint16(iftype)}}),
		},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, Data: heMAC},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, Data: hePHY},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET, Data: ath12kHECapMCSSet},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE, Data: ath12kHECapPPE},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, Data: ehtMAC},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, Data: ehtPHY},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET, Data: ath12kEHTCapMCSSet},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA, Data: ath12kHE6GHzCapa},
	}
}

// TestLinux_parseBandIftypeDataMultipleIftypes verifies that every interface
// type of a band is decoded, in the order the kernel reports them.  A band of
// an ath12k device reports three: station, AP and mesh point.
func TestLinux_parseBandIftypeDataMultipleIftypes(t *testing.T) {
	entries := [][]netlink.Attribute{
		ath12kIftypeAttrs(InterfaceTypeStation, ath12kHECapMACStation, ath12kHECapPHYStation, ath12kEHTCapMAC, ath12kEHTCapPHYStation),
		ath12kIftypeAttrs(InterfaceTypeAP, ath12kHECapMACAP, ath12kHECapPHYAP, ath12kEHTCapMAC, ath12kEHTCapPHYAP),
		ath12kIftypeAttrs(InterfaceTypeMeshPoint, ath12kHECapMACMesh, ath12kHECapPHYMesh, ath12kEHTCapMACMesh, ath12kEHTCapPHYMesh),
	}

	// The kernel indexes the interface types of a band from one.
	var attrs []netlink.Attribute
	for i, e := range entries {
		attrs = append(attrs, netlink.Attribute{
			Type: uint16(i + 1),
			Data: mustMarshalAttributes(e),
		})
	}

	he, eht, err := parseBandIftypeData(mustMarshalAttributes(attrs))
	if err != nil {
		t.Fatalf("failed to parse band interface type data: %v", err)
	}

	want := [][]InterfaceType{
		{InterfaceTypeStation},
		{InterfaceTypeAP},
		{InterfaceTypeMeshPoint},
	}

	var gotHE, gotEHT [][]InterfaceType
	for i := range he {
		gotHE = append(gotHE, he[i].InterfaceTypes)
	}
	for i := range eht {
		gotEHT = append(gotEHT, eht[i].InterfaceTypes)
	}

	if diff := cmp.Diff(want, gotHE); diff != "" {
		t.Errorf("unexpected HE interface types (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(want, gotEHT); diff != "" {
		t.Errorf("unexpected EHT interface types (-want +got):\n%s", diff)
	}

	// Each interface type carries its own capabilities: only the AP
	// advertises itself as an MU beamformer, and only the mesh point lacks
	// EPCS priority access.
	if eht[0].MUBeamformer320MHz || !eht[1].MUBeamformer320MHz {
		t.Error("expected only the AP to advertise MU beamforming at 320MHz")
	}

	if !eht[0].EPCSPriorityAccess || eht[2].EPCSPriorityAccess {
		t.Error("expected only the mesh point to lack EPCS priority access")
	}
}

// narrowIftypeAttrs builds the attributes of an interface type which advertises
// no channel width beyond 20MHz, and no PPE thresholds.  No device to hand
// reports this, so the capability fields are synthetic; only the lengths and
// the bits which select the MCS maps matter.
func narrowIftypeAttrs(iftype InterfaceType, ehtMCSSet []byte) []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: unix.NL80211_BAND_IFTYPE_ATTR_IFTYPES,
			Data: mustMarshalAttributes([]netlink.Attribute{{Type: uint16(iftype)}}),
		},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, Data: make([]byte, heMACCapLen)},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, Data: make([]byte, hePHYCapLen)},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET, Data: mt7925HECapMCSSet},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE, Data: make([]byte, 25)},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, Data: make([]byte, ehtMACCapLen)},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, Data: make([]byte, ehtPHYCapLen)},
		{Type: unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET, Data: ehtMCSSet},
	}
}

// TestLinux_parseBandAttributesIftypeData verifies that the capabilities of a
// band's interface types are attached to that band, and that the repeated
// messages the kernel sends for a band do not accumulate duplicates.
func TestLinux_parseBandAttributesIftypeData(t *testing.T) {
	// A band other than the first, to check the indexing.
	const band = 2

	nlband := netlink.Attribute{
		Type: band,
		Data: mustMarshalAttributes([]netlink.Attribute{{
			Type: unix.NL80211_BAND_ATTR_IFTYPE_DATA,
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: 1,
				Data: mustMarshalAttributes(ath12kIftypeAttrs(
					InterfaceTypeAP,
					ath12kHECapMACAP, ath12kHECapPHYAP,
					ath12kEHTCapMAC, ath12kEHTCapPHYAP,
				)),
			}}),
		}}),
	}

	p := new(PHY)
	if err := p.parseBandAttributes(nlband); err != nil {
		t.Fatalf("failed to parse band attributes: %v", err)
	}

	// Bands are indexed by band number, so the earlier bands exist but are
	// empty.
	if diff := cmp.Diff(band+1, len(p.BandAttributes)); diff != "" {
		t.Fatalf("unexpected number of bands (-want +got):\n%s", diff)
	}

	ba := p.BandAttributes[band]

	if diff := cmp.Diff(1, len(ba.HECapabilities)); diff != "" {
		t.Fatalf("unexpected number of HE capability sets (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(1, len(ba.EHTCapabilities)); diff != "" {
		t.Fatalf("unexpected number of EHT capability sets (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]InterfaceType{InterfaceTypeAP}, ba.EHTCapabilities[0].InterfaceTypes); diff != "" {
		t.Errorf("unexpected interface types (-want +got):\n%s", diff)
	}

	// 320MHz support adds a third EHT-MCS map.
	if diff := cmp.Diff(3, len(ba.EHTCapabilities[0].SupportedMCSSets)); diff != "" {
		t.Errorf("unexpected number of EHT-MCS sets (-want +got):\n%s", diff)
	}

	// The kernel sends several messages for one band, and only the first
	// carries the capabilities; a repeat must not duplicate them.
	if err := p.parseBandAttributes(nlband); err != nil {
		t.Fatalf("failed to parse band attributes again: %v", err)
	}

	if diff := cmp.Diff(1, len(ba.EHTCapabilities)); diff != "" {
		t.Errorf("unexpected number of EHT capability sets after a repeated message (-want +got):\n%s", diff)
	}
}

// TestLinux_decodeCapabilityEncodings exercises the subfields which are decoded
// from an encoding into a real unit, since a transposed table entry there is
// invisible in the capability bits themselves.
func TestLinux_decodeCapabilityEncodings(t *testing.T) {
	t.Run("EHT maximum MPDU length", func(t *testing.T) {
		// The length lives in the top two bits of the first byte.
		for encoding, want := range map[byte]int{0: 3895, 1: 7991, 2: 11454, 3: 0} {
			var ehtcap EHTCapabilities
			decodeEHTMACCapabilities(&ehtcap, []byte{encoding << 6, 0x00})

			if diff := cmp.Diff(want, ehtcap.MaxMPDULength); diff != "" {
				t.Errorf("unexpected length for encoding %d (-want +got):\n%s", encoding, diff)
			}
		}
	})

	t.Run("EHT common nominal packet padding", func(t *testing.T) {
		for encoding, want := range map[byte]int{0: 0, 1: 8, 2: 16, 3: 20} {
			var ehtcap EHTCapabilities
			phy := make([]byte, ehtPHYCapLen)
			phy[5] = encoding << 4

			decodeEHTPHYCapabilities(&ehtcap, phy)

			if diff := cmp.Diff(want, ehtcap.CommonNominalPacketPadding); diff != "" {
				t.Errorf("unexpected padding for encoding %d (-want +got):\n%s", encoding, diff)
			}
		}
	})

	t.Run("HE minimum fragment size and padding duration", func(t *testing.T) {
		for encoding, want := range map[byte]int{0: 0, 1: 128, 2: 256, 3: 512} {
			var hecap HECapabilities
			mac := make([]byte, heMACCapLen)
			mac[1] = encoding

			decodeHEMACCapabilities(&hecap, mac)

			if diff := cmp.Diff(want, hecap.MinFragmentSize); diff != "" {
				t.Errorf("unexpected fragment size for encoding %d (-want +got):\n%s", encoding, diff)
			}
		}

		// The reserved encoding is reported as no padding.
		for encoding, want := range map[byte]int{0: 0, 1: 8, 2: 16, 3: 0} {
			var hecap HECapabilities
			mac := make([]byte, heMACCapLen)
			mac[1] = encoding << 2

			decodeHEMACCapabilities(&hecap, mac)

			if diff := cmp.Diff(want, hecap.TriggerFrameMACPaddingDuration); diff != "" {
				t.Errorf("unexpected duration for encoding %d (-want +got):\n%s", encoding, diff)
			}
		}
	})

	t.Run("HE nominal packet padding", func(t *testing.T) {
		for encoding, want := range map[byte]int{0: 0, 1: 8, 2: 16, 3: 0} {
			var hecap HECapabilities
			phy := make([]byte, hePHYCapLen)
			phy[9] = encoding << 6

			decodeHEPHYCapabilities(&hecap, phy)

			if diff := cmp.Diff(want, hecap.NominalPacketPadding); diff != "" {
				t.Errorf("unexpected padding for encoding %d (-want +got):\n%s", encoding, diff)
			}
		}
	})

	t.Run("HE 6GHz maximum lengths", func(t *testing.T) {
		// Maximum MPDU length, in the same encoding as VHT uses.
		for encoding, want := range map[uint16]int{0: 3895, 1: 7991, 2: 11454, 3: 0} {
			got := decodeHE6GHzCapabilities(encoding << 6)

			if diff := cmp.Diff(want, got.MaxMPDULength); diff != "" {
				t.Errorf("unexpected length for encoding %d (-want +got):\n%s", encoding, diff)
			}
		}

		// The A-MPDU length exponent extends the 8KiB minimum.
		for encoding, want := range map[uint16]int{0: 8191, 3: 65535, 7: 1048575} {
			got := decodeHE6GHzCapabilities(encoding << 3)

			if diff := cmp.Diff(want, got.MaxRxAMPDULength); diff != "" {
				t.Errorf("unexpected A-MPDU length for exponent %d (-want +got):\n%s", encoding, diff)
			}
		}

		// The minimum MPDU start spacing doubles from 1/4 microsecond.
		for encoding, want := range map[uint16]time.Duration{0: 0, 1: 250, 2: 500, 7: 16000} {
			got := decodeHE6GHzCapabilities(encoding)

			if diff := cmp.Diff(want*time.Nanosecond, got.MinMPDUStartSpacing); diff != "" {
				t.Errorf("unexpected spacing for encoding %d (-want +got):\n%s", encoding, diff)
			}
		}
	})
}

// The Supported MCS Set fields reported by both an MT7925 and an 8devices
// Kiwi-DVK: MCS 0-15 for HT, and MCS 0-9 with one and two spatial streams for
// VHT.  Neither device specifies a highest data rate.
var (
	twoStreamHTMCSSet = [16]byte{
		0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	}

	twoStreamVHTMCSSet = [8]byte{0xfa, 0xff, 0x00, 0x00, 0xfa, 0xff, 0x00, 0x20}
)

func TestLinux_decodeHTMCSSet(t *testing.T) {
	// The receive bitmask holds one bit per MCS index, so a device
	// supporting every index up to hi sets the first hi+1 bits.
	upTo := func(hi int) []int {
		var mcs []int
		for i := range hi + 1 {
			mcs = append(mcs, i)
		}
		return mcs
	}

	tests := []struct {
		name string
		mcs  [16]byte
		want HTCapabilities
	}{
		{
			name: "two streams",
			mcs:  twoStreamHTMCSSet,
			want: HTCapabilities{
				RxMCS: upTo(15),
				// The transmit set is defined and matches the
				// receive set, so the stream count and unequal
				// modulation fields carry no meaning.
				TxMCSSetDefined:     true,
				TxMaxSpatialStreams: 1,
			},
		},
		{
			name: "four streams with unequal modulation",
			mcs: [16]byte{
				// MCS 0-31, plus index 32, the 40MHz duplicate.
				0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
				0x00, 0x00,
				// A highest receive rate of 300Mb/s.
				0x2c, 0x01,
				// Defined, differing, four streams, unequal.
				0x1f, 0x00, 0x00, 0x00,
			},
			want: HTCapabilities{
				RxMCS:               upTo(32),
				RxHighestRate:       300,
				TxMCSSetDefined:     true,
				TxRxMCSSetNotEqual:  true,
				TxMaxSpatialStreams: 4,
				TxUnequalModulation: true,
			},
		},
		{
			name: "no transmit set defined",
			mcs: [16]byte{
				0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			want: HTCapabilities{
				RxMCS:               upTo(7),
				TxMaxSpatialStreams: 1,
			},
		},
		{
			// The highest index the bitmask can express; the three
			// bits above it are reserved and must be ignored.
			name: "highest index only",
			mcs: [16]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			want: HTCapabilities{
				RxMCS:               []int{72, 73, 74, 75, 76},
				TxMaxSpatialStreams: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			htcap := HTCapabilities{SupportedMCS: tt.mcs}
			decodeHTMCSSet(&htcap)

			want := tt.want
			want.SupportedMCS = tt.mcs

			if diff := cmp.Diff(want, htcap); diff != "" {
				t.Errorf("unexpected HT MCS set (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLinux_decodeVHTMCSSet(t *testing.T) {
	tests := []struct {
		name string
		mcs  [8]byte
		want VHTCapabilities
	}{
		{
			name: "two streams",
			mcs:  twoStreamVHTMCSSet,
			want: VHTCapabilities{
				RxHighestMCS:         [8]int{9, 9, -1, -1, -1, -1, -1, -1},
				TxHighestMCS:         [8]int{9, 9, -1, -1, -1, -1, -1, -1},
				ExtendedNSSBWCapable: true,
			},
		},
		{
			// Every per-stream encoding in one map: MCS 0-7, 0-8,
			// 0-9, then unsupported.
			name: "every stream encoding",
			mcs: [8]byte{
				0xe4, 0xff,
				// 866Mb/s, and four space-time streams.
				0x62, 0x83,
				0xe4, 0xff,
				// 866Mb/s, and capable of extended NSS BW.
				0x62, 0x23,
			},
			want: VHTCapabilities{
				RxHighestMCS:         [8]int{7, 8, 9, -1, -1, -1, -1, -1},
				TxHighestMCS:         [8]int{7, 8, 9, -1, -1, -1, -1, -1},
				RxHighestRate:        866,
				TxHighestRate:        866,
				MaxNSTSTotal:         4,
				ExtendedNSSBWCapable: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vhtcap := VHTCapabilities{SupportedMCS: tt.mcs}
			decodeVHTMCSSet(&vhtcap)

			want := tt.want
			want.SupportedMCS = tt.mcs

			if diff := cmp.Diff(want, vhtcap); diff != "" {
				t.Errorf("unexpected VHT MCS set (-want +got):\n%s", diff)
			}
		})
	}
}

// TestLinux_parseBandAttributesMCSSets verifies that the HT and VHT MCS sets of
// a band are decoded as the band attributes are parsed.
func TestLinux_parseBandAttributesMCSSets(t *testing.T) {
	p := new(PHY)
	err := p.parseBandAttributes(netlink.Attribute{
		Type: 0,
		Data: mustMarshalAttributes([]netlink.Attribute{
			{Type: unix.NL80211_BAND_ATTR_HT_MCS_SET, Data: twoStreamHTMCSSet[:]},
			{Type: unix.NL80211_BAND_ATTR_VHT_MCS_SET, Data: twoStreamVHTMCSSet[:]},
		}),
	})
	if err != nil {
		t.Fatalf("failed to parse band attributes: %v", err)
	}

	ba := p.BandAttributes[0]

	if diff := cmp.Diff(16, len(ba.HTCapabilities.RxMCS)); diff != "" {
		t.Errorf("unexpected number of HT MCS indices (-want +got):\n%s", diff)
	}

	want := [8]int{9, 9, -1, -1, -1, -1, -1, -1}
	if diff := cmp.Diff(want, ba.VHTCapabilities.RxHighestMCS); diff != "" {
		t.Errorf("unexpected VHT receive MCS (-want +got):\n%s", diff)
	}
}
