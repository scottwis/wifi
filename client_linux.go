//go:build linux

package wifi

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/unix"
)

var (
	ErrNotSupported      = errors.New("not supported")
	ErrScanGroupNotFound = errors.New("scan multicast group unavailable")
	ErrScanAborted       = errors.New("scan aborted by the kernel")
	ErrScanValidation    = errors.New("scan validation failed")
)

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type client struct {
	c             *genetlink.Conn
	familyID      uint16
	familyVersion uint8

	// scan is used to synchronize access to the Scan method.
	scan sync.Mutex
}

// newClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func newClient() (*client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	// Make a best effort to apply the strict options set to provide better
	// errors and validation. We don't apply Strict in the constructor because
	// this library is widely used on a range of kernels and we can't guarantee
	// it will always work on older kernels.
	for _, o := range []netlink.ConnOption{
		netlink.ExtendedAcknowledge,
		netlink.GetStrictCheck,
	} {
		_ = c.SetOption(o, true)
	}

	return initClient(c)
}

func initClient(c *genetlink.Conn) (*client, error) {
	family, err := c.GetFamily(unix.NL80211_GENL_NAME)
	if err != nil {
		// Ensure the genl socket is closed on error to avoid leaking file
		// descriptors.
		_ = c.Close()
		return nil, err
	}

	return &client{
		c:             c,
		familyID:      family.ID,
		familyVersion: family.Version,

		scan: sync.Mutex{},
	}, nil
}

// Close closes the client's generic netlink connection.
func (c *client) Close() error { return c.c.Close() }

// Interfaces requests that nl80211 return a list of all WiFi interfaces present
// on this system.
func (c *client) Interfaces() ([]*Interface, error) {
	// Ask nl80211 to dump a list of all WiFi interfaces
	msgs, err := c.get(
		unix.NL80211_CMD_GET_INTERFACE,
		netlink.Dump,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return ParseInterfaces(msgs)
}

// PHYs requests that nl80211 return information for all wireless physical
// devices.
func (c *client) PHYs() ([]*PHY, error) {
	return c.getPHYs(nil)
}

// getPHYs is the back-end for PHY() and PHYs(): building and making the netlink
// call, and parsing the response.
func (c *client) getPHYs(n *uint32) ([]*PHY, error) {
	// The kernel, as of 3713b4e364eff (3.10), doesn't emit all information
	// unless SplitWiphyDump is set.  We could check for it by issuing
	// CmdGetProtocolFeatures and seeing if ProtocolFeatureSplitWiphyDump is
	// set, if we care about kernels that old ...
	msgs, err := c.get(unix.NL80211_CMD_GET_WIPHY, netlink.Dump, nil, func(ae *netlink.AttributeEncoder) {
		ae.Flag(unix.NL80211_ATTR_SPLIT_WIPHY_DUMP, true)
		if n != nil {
			ae.Uint32(unix.NL80211_ATTR_WIPHY, *n)
		}
	})
	if err != nil {
		return nil, err
	}
	return parsePHYs(msgs)
}

// Connect starts connecting the interface to the specified ssid.
func (c *client) Connect(ifi *Interface, ssid string) error {
	// Ask nl80211 to connect to the specified SSID.
	_, err := c.get(
		unix.NL80211_CMD_CONNECT,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
		},
	)
	return err
}

// Disconnect disconnects the interface.
func (c *client) Disconnect(ifi *Interface) error {
	// Ask nl80211 to disconnect.
	_, err := c.get(
		unix.NL80211_CMD_DISCONNECT,
		netlink.Acknowledge,
		ifi,
		nil,
	)
	return err
}

// ConnectWPAPSK starts connecting the interface to the specified SSID using
// WPA.
func (c *client) ConnectWPAPSK(ifi *Interface, ssid, psk string) error {
	support, err := c.checkExtFeature(ifi, unix.NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK)
	if err != nil {
		return err
	}
	if !support {
		return ErrNotSupported
	}

	// Ask nl80211 to connect to the specified SSID with key..
	_, err = c.get(
		unix.NL80211_CMD_CONNECT,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// TODO(mdlayher): document these or build from bitflags.
			const (
				cipherSuites = 0xfac04
				akmSuites    = 0xfac02
			)

			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_WPA_VERSIONS, unix.NL80211_WPA_VERSION_2)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITE_GROUP, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITES_PAIRWISE, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_AKM_SUITES, akmSuites)
			ae.Flag(unix.NL80211_ATTR_WANT_1X_4WAY_HS, true)
			ae.Bytes(
				unix.NL80211_ATTR_PMK,
				wpaPassphrase([]byte(ssid), []byte(psk)),
			)
			ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
		},
	)
	return err
}

// wpaPassphrase computes a WPA passphrase given an SSID and preshared key.
func wpaPassphrase(ssid, psk []byte) []byte {
	return pbkdf2.Key(psk, ssid, 4096, 32, sha1.New)
}

// BSS requests that nl80211 return the BSS for the specified Interface.
func (c *client) BSS(ifi *Interface) (*BSS, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SCAN,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			if ifi.HardwareAddr != nil {
				ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
			}
		},
	)
	if err != nil {
		return nil, err
	}

	return parseBSS(msgs)
}

// AccessPoints requests that nl80211 return all currently known BSS
// from the specified Interface.
func (c *client) AccessPoints(ifi *Interface) ([]*BSS, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SCAN,
		netlink.Dump,
		ifi,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return parseGetScanResult(msgs)
}

// StationInfo requests that nl80211 return all station info for the specified
// Interface.
func (c *client) StationInfo(ifi *Interface) ([]*StationInfo, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_STATION,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			if ifi.HardwareAddr != nil {
				ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
			}
		},
	)
	if err != nil {
		return nil, err
	}

	stations := make([]*StationInfo, len(msgs))
	for i := range msgs {
		if stations[i], err = ParseStationInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}

	return stations, nil
}

// SurveyInfo requests that nl80211 return a list of survey information for the
// specified Interface.
func (c *client) SurveyInfo(ifi *Interface) ([]*SurveyInfo, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SURVEY,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			if ifi.HardwareAddr != nil {
				ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
			}
		},
	)
	if err != nil {
		return nil, err
	}

	surveys := make([]*SurveyInfo, len(msgs))
	for i := range msgs {
		if surveys[i], err = parseSurveyInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}
	return surveys, nil
}

// Scan requests that nl80211 perform a scan for new access points using
// the specified Interface. This process is long running and uses
// a separate connection to nl80211.
//
// Use context.WithDeadline to set a timeout.
//
// If a scan is already in progress, this function will return a syscall.EBUSY
// error. If the response cannot be validated, the returned error
// will include ErrScanValidation.
//
// Use func AccessPoints to retrieve the results.
func (c *client) Scan(ctx context.Context, ifi *Interface) error {
	c.scan.Lock()
	defer c.scan.Unlock()

	// use secondary connection for multicast receives
	conn, err := genetlink.Dial(&netlink.Config{Strict: true})
	if err != nil {
		return err
	}

	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		err := conn.SetDeadline(deadline)
		if err != nil {
			return err
		}
	}

	family, err := conn.GetFamily(unix.NL80211_GENL_NAME)
	if err != nil {
		return err
	}

	var id uint32
	for _, group := range family.Groups {
		if group.Name == unix.NL80211_MULTICAST_GROUP_SCAN {
			err = conn.JoinGroup(group.ID)
			if err != nil {
				return err
			}

			id = group.ID
			break
		}
	}

	if id == 0 {
		return ErrScanGroupNotFound
	}

	// Leave group on exit. Err is non-actionable
	defer func() { _ = conn.LeaveGroup(id) }()

	enc := netlink.NewAttributeEncoder()
	enc.Nested(unix.NL80211_ATTR_SCAN_SSIDS, func(ae *netlink.AttributeEncoder) error {
		ae.Bytes(unix.NL80211_SCHED_SCAN_MATCH_ATTR_SSID, nlenc.Bytes(""))
		return nil
	})

	ifi.encode(enc)

	data, err := enc.Encode()
	if err != nil {
		return err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: unix.NL80211_CMD_TRIGGER_SCAN,
			Version: c.familyVersion,
		},
		Data: data,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	result := make(chan error, 1)
	go func(ctx context.Context, conn *genetlink.Conn, ifiIndex int, familyVersion uint8, result chan<- error) {

		defer close(result)
		result <- listenNewScanResults(ctx, conn, ifiIndex, familyVersion)

	}(ctx, conn, ifi.Index, c.familyVersion, result)

	flags := netlink.Request | netlink.Acknowledge

	_, err = conn.Send(req, family.ID, flags)
	if err != nil {
		cancel()
	}

	err2 := <-result

	return errors.Join(err, err2)
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *client) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the connection.
func (c *client) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the connection.
func (c *client) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

// ReloadRegulatoryDatabase reloads the wireless regulatory database.
//
// This can be used if cfg80211 was built into the kernel and the wireless regulatory database
// was not available during early boot.
//
// See https://wireless.docs.kernel.org/en/latest/en/developers/regulatory/wireless-regdb.html
func (c *client) ReloadRegulatoryDatabase() error {
	_, err := c.get(
		unix.NL80211_CMD_RELOAD_REGDB,
		netlink.Acknowledge,
		nil,
		nil,
	)

	return err
}

// GetRegulatoryDomain gets the system-wide regulatory region used by all nl80211 devices.
// See
// - https://wireless.docs.kernel.org/en/latest/en/developers/regulatory/wireless-regdb.html
// - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/wireless/nl80211.c?h=a55f7f5f29b32c2c53cc291899cf9b0c25a07f7c#n9920
func (c *client) GetRegulatoryDomain() (*RegulatoryDomain, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_REG,
		netlink.Request,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	// We expect one message which represents the global regulatory domain.
	if len(msgs) == 0 {
		return nil, os.ErrNotExist
	}

	attrs, err := netlink.UnmarshalAttributes(msgs[0].Data)
	if err != nil {
		return nil, err
	}

	var domain RegulatoryDomain
	if err := domain.parseAttributes(attrs); err != nil {
		return nil, err
	}

	return &domain, nil
}

// SetRegulatoryRegion sets the system-wide regulatory region used by all nl80211 devices.
// You may need to call [client.ReloadRegulatoryDatabase] first to ensure the region is updated correctly.
//
// region must be an ISO 3166-1 alpha-2 country code (e.g. "GB" or "US").
//
// See https://wireless.docs.kernel.org/en/latest/en/developers/regulatory/wireless-regdb.html
func (c *client) SetRegulatoryRegion(region string, hint RegulatoryHint) error {
	_, err := c.get(
		unix.NL80211_CMD_REQ_SET_REG,
		netlink.Acknowledge,
		nil,
		func(ae *netlink.AttributeEncoder) {
			ae.String(unix.NL80211_ATTR_REG_ALPHA2, region)
			ae.Uint32(unix.NL80211_ATTR_USER_REG_HINT_TYPE, uint32(hint))
		},
	)

	return err
}

// get performs a request/response interaction with nl80211.
func (c *client) get(
	cmd uint8,
	flags netlink.HeaderFlags,
	ifi *Interface,
	// May be nil; used to apply optional parameters.
	params func(ae *netlink.AttributeEncoder),
) ([]genetlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	ifi.encode(ae)
	if params != nil {
		// Optionally apply more parameters to the attribute encoder.
		params(ae)
	}

	// Note: don't send netlink.Acknowledge or we get an extra message back from
	// the kernel which doesn't seem useful as of now.
	return c.execute(cmd, flags, ae)
}

// execute executes the specified command with additional header flags and input
// netlink request attributes. The netlink.Request header flag is automatically
// set.
func (c *client) execute(
	cmd uint8,
	flags netlink.HeaderFlags,
	ae *netlink.AttributeEncoder,
) ([]genetlink.Message, error) {
	b, err := ae.Encode()
	if err != nil {
		return nil, err
	}

	return c.c.Execute(
		genetlink.Message{
			Header: genetlink.Header{
				Command: cmd,
				Version: c.familyVersion,
			},
			Data: b,
		},
		// Always pass the genetlink family ID and request flag.
		c.familyID,
		netlink.Request|flags,
	)
}

// listenNewScanResults listens for new scan results or scan abort messages
// from the netlink connection. It processes the messages associated with the
// specified interface index and family version, verifying attributes and
// handling context cancellations.
//
// The caller should not receive on the given connection and is responsible
// for closing it.
func listenNewScanResults(ctx context.Context, conn *genetlink.Conn, ifiIndex int, familyVersion uint8) error {
	for ctx.Err() == nil {
		msgs, _, err := conn.Receive()
		if err != nil {
			return err
		}

		// test for context cancellation and abandon work if so
		if ctx.Err() != nil {
			return err
		}

		for _, msg := range msgs {
			if msg.Header.Version != familyVersion {
				break
			}

			switch msg.Header.Command {
			case unix.NL80211_CMD_SCAN_ABORTED:
				return ErrScanAborted
			case unix.NL80211_CMD_NEW_SCAN_RESULTS:
				// attempt to verify the interface
				attrs, err := netlink.UnmarshalAttributes(msg.Data)
				if err != nil {
					return errors.Join(ErrScanValidation, err)
				}

				var intf Interface
				if err := (&intf).parseAttributes(attrs); err != nil {
					return errors.Join(ErrScanValidation, err)
				}

				if ifiIndex != intf.Index {
					continue
				}

				return nil
			default:
				continue
			}

		}
	}

	return ctx.Err()
}

// parseGetScanResult parses all the BSS from nl80211 CMD_GET_SCAN response messages.
func parseGetScanResult(msgs []genetlink.Message) ([]*BSS, error) {
	// reimplementing https://github.com/mdlayher/wifi/pull/79
	bsss := make([]*BSS, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var bss BSS
		for _, a := range attrs {
			if a.Type != unix.NL80211_ATTR_BSS {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if !attrsContain(nattrs, unix.NL80211_BSS_STATUS) {
				bss.Status = BSSStatusNotAssociated
			}

			if err := (&bss).parseAttributes(nattrs); err != nil {
				continue
			}
		}
		bsss = append(bsss, &bss)
	}
	return bsss, nil
}

// parseInterfaces parses zero or more Interfaces from nl80211 interface
// messages.
func ParseInterfaces(msgs []genetlink.Message) ([]*Interface, error) {
	ifis := make([]*Interface, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var ifi Interface
		if err := (&ifi).parseAttributes(attrs); err != nil {
			return nil, err
		}

		ifis = append(ifis, &ifi)
	}

	return ifis, nil
}

// encode provides an encoding function for ifi's attributes. If ifi is nil,
// encode is a no-op.
func (ifi *Interface) encode(ae *netlink.AttributeEncoder) {
	if ifi == nil {
		return
	}

	// Mandatory.
	ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
}

// idAttrs returns the netlink attributes required from an Interface to retrieve
// more data about it.
func (ifi *Interface) idAttrs() []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: unix.NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
		{
			Type: unix.NL80211_ATTR_MAC,
			Data: ifi.HardwareAddr,
		},
	}
}

// parseAttributes parses netlink attributes into an Interface's fields.
func (ifi *Interface) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_IFINDEX:
			ifi.Index = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_ATTR_IFNAME:
			ifi.Name = nlenc.String(a.Data)
		case unix.NL80211_ATTR_MAC:
			ifi.HardwareAddr = net.HardwareAddr(a.Data)
		case unix.NL80211_ATTR_WIPHY:
			ifi.PHY = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_ATTR_IFTYPE:
			// NOTE: InterfaceType copies the ordering of nl80211's interface type
			// constants.  This may not be the case on other operating systems.
			ifi.Type = InterfaceType(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_ATTR_WDEV:
			ifi.Device = int(binary.NativeEndian.Uint64(a.Data))
		case unix.NL80211_ATTR_WIPHY_FREQ:
			ifi.Frequency = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_ATTR_CHANNEL_WIDTH:
			ifi.ChannelWidth = ChannelWidth(binary.NativeEndian.Uint32(a.Data))
		}
	}

	return nil
}

// parseBSS parses a single BSS with a status attribute from nl80211 BSS messages.
func parseBSS(msgs []genetlink.Message) (*BSS, error) {
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		for _, a := range attrs {
			if a.Type != unix.NL80211_ATTR_BSS {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			// The BSS which is associated with an interface will have a status
			// attribute
			if !attrsContain(nattrs, unix.NL80211_BSS_STATUS) {
				continue
			}

			var bss BSS
			if err := (&bss).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			return &bss, nil
		}
	}

	return nil, os.ErrNotExist
}

func parsePHYs(msgs []genetlink.Message) ([]*PHY, error) {
	phys := make([]*PHY, 0)
	var phy *PHY
	curphynum := -1
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		// Because we get a single stream of messages spanning multiple
		// PHYs, we have to peek into the attributes to see if it's the
		// same PHY as we've been processing.
		phynum, err := phyNumber(attrs)
		if err != nil {
			return nil, err
		}
		if phynum != curphynum {
			phy = new(PHY)
			phy.Extra = make(map[uint16][]byte, 0)
			phys = append(phys, phy)
			curphynum = phynum
		}

		if err := phy.parseAttributes(attrs); err != nil {
			return nil, err
		}
	}
	return phys, nil
}

// phyNumber extracts the first integer device index (AttrWiphy) from a list of
// netlink attributes.
func phyNumber(attrs []netlink.Attribute) (int, error) {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_WIPHY:
			return int(binary.NativeEndian.Uint32(a.Data)), nil
		}
	}
	return 0, fmt.Errorf("there was no wiphy attribute")
}

// parseAttributes parses netlink attributes into a PHY's fields.
func (p *PHY) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_WIPHY:
			p.Index = int(binary.NativeEndian.Uint32(a.Data))

		case unix.NL80211_ATTR_WIPHY_NAME:
			p.Name = nlenc.String(a.Data)

		case unix.NL80211_ATTR_SUPPORTED_IFTYPES:
			// This contains nested attributes with no data; the
			// data we care about is the type.
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for _, na := range nattrs {
				p.SupportedIftypes = append(p.SupportedIftypes, InterfaceType(na.Type))
			}

		case unix.NL80211_ATTR_SOFTWARE_IFTYPES:
			// This contains nested attributes with no data; the
			// data we care about is the type.
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for _, na := range nattrs {
				p.SoftwareIftypes = append(p.SoftwareIftypes, InterfaceType(na.Type))
			}

		case unix.NL80211_ATTR_WIPHY_BANDS:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for i, band := range nattrs {
				// band.Type has the band number
				err := p.parseBandAttributes(band)
				if err != nil {
					return fmt.Errorf("could not decode band %d (attr#%d) data: %s",
						band.Type, i, err)
				}
			}

		case unix.NL80211_ATTR_INTERFACE_COMBINATIONS:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for i, combo := range nattrs {
				c, err := parseCombo(combo)
				if err != nil {
					return fmt.Errorf("could not decode combo %d data: %s", i, err)
				}
				p.InterfaceCombinations = append(p.InterfaceCombinations, *c)
			}

		default:
			p.Extra[a.Type] = a.Data
		}
	}
	return nil
}

// parseCombo parses a netlink attribute into an InterfaceCombination.
func parseCombo(comboNLA netlink.Attribute) (*InterfaceCombination, error) {
	attrs, err := netlink.UnmarshalAttributes(comboNLA.Data)
	if err != nil {
		return nil, err
	}

	combo := &InterfaceCombination{}
	for _, attr := range attrs {
		switch attr.Type {
		case unix.NL80211_IFACE_COMB_LIMITS:
			lattrs, err := netlink.UnmarshalAttributes(attr.Data)
			if err != nil {
				return nil, err
			}

			for _, l := range lattrs {
				comboLimit := InterfaceCombinationLimit{}
				ltypes, err := netlink.UnmarshalAttributes(l.Data)
				if err != nil {
					return nil, err
				}

				for _, la := range ltypes {
					switch la.Type {
					case unix.NL80211_IFACE_LIMIT_MAX:
						comboLimit.Max = int(binary.NativeEndian.Uint32(la.Data))
					case unix.NL80211_IFACE_LIMIT_TYPES:
						types, err := netlink.UnmarshalAttributes(la.Data)
						if err != nil {
							return nil, err
						}

						for _, typ := range types {
							comboLimit.InterfaceTypes = append(comboLimit.InterfaceTypes, InterfaceType(typ.Type))
						}
					}
				}
				combo.CombinationLimits = append(combo.CombinationLimits, comboLimit)
			}

		case unix.NL80211_IFACE_COMB_NUM_CHANNELS:
			combo.NumChannels = int(binary.NativeEndian.Uint32(attr.Data))

		case unix.NL80211_IFACE_COMB_MAXNUM:
			combo.Total = int(binary.NativeEndian.Uint32(attr.Data))

		case unix.NL80211_IFACE_COMB_STA_AP_BI_MATCH:
			combo.StaApBiMatch = true
		}
	}
	return combo, nil
}

// parseBandAttributes parses a netlink attribute into the band-specific data of
// a PHY.
func (p *PHY) parseBandAttributes(nlband netlink.Attribute) error {
	attrs, err := netlink.UnmarshalAttributes(nlband.Data)
	if err != nil {
		return err
	}

	// We'll get called multiple times for individual attributes of a band,
	// so be sure to use the right element of the BandAttributes array, or
	// add new ones if we haven't seen the band before.  The expectation is
	// that we'll get them in order, 0..n, but this should work for any
	// ordering.
	for int(nlband.Type)+1 > len(p.BandAttributes) {
		ba := &BandAttributes{}
		p.BandAttributes = append(p.BandAttributes, *ba)
	}
	ba := &p.BandAttributes[nlband.Type]

	for _, attr := range attrs {
		switch attr.Type {
		case unix.NL80211_BAND_ATTR_HT_CAPA:
			ba.HTCapabilities = decodeHTCapabilities(ba.HTCapabilities, binary.NativeEndian.Uint16(attr.Data))

		case unix.NL80211_BAND_ATTR_HT_AMPDU_FACTOR:
			exponent := attr.Data[0]
			// The exponent comes from three bits of OTA data, but
			// netlink gives it to us as an 8-bit value.
			if exponent < 4 {
				// If we haven't seen BandAttrHtCapa yet, we
				// need to create the struct first.
				if ba.HTCapabilities == nil {
					ba.HTCapabilities = new(HTCapabilities)
				}
				ba.HTCapabilities.MaxRxAMPDULength = (1 << (13 + exponent)) - 1
			}

		case unix.NL80211_BAND_ATTR_HT_AMPDU_DENSITY:
			spacing := attr.Data[0]
			if spacing > 0 {
				ba.MinRxAMPDUSpacing = (1 << (spacing - 1)) * time.Microsecond / 4
			}

		case unix.NL80211_BAND_ATTR_VHT_CAPA:
			ba.VHTCapabilities = decodeVHTCapabilities(ba.VHTCapabilities, binary.NativeEndian.Uint32(attr.Data))
		case unix.NL80211_BAND_ATTR_HT_MCS_SET:
			if ba.HTCapabilities == nil {
				ba.HTCapabilities = new(HTCapabilities)
			}
			copy(ba.HTCapabilities.SupportedMCS[:], attr.Data)
			decodeHTMCSSet(ba.HTCapabilities)
		case unix.NL80211_BAND_ATTR_VHT_MCS_SET:
			if ba.VHTCapabilities == nil {
				ba.VHTCapabilities = new(VHTCapabilities)
			}
			copy(ba.VHTCapabilities.SupportedMCS[:], attr.Data)
			decodeVHTMCSSet(ba.VHTCapabilities)

		case unix.NL80211_BAND_ATTR_IFTYPE_DATA:
			hecaps, ehtcaps, err := parseBandIftypeData(attr.Data)
			if err != nil {
				return err
			}
			ba.HECapabilities = hecaps
			ba.EHTCapabilities = ehtcaps

		case unix.NL80211_BAND_ATTR_RATES:
			nattrs, err := netlink.UnmarshalAttributes(attr.Data)
			if err != nil {
				return err
			}
			// It doesn't look like we need to take as much care to
			// build up the BitrateAttributes array as we do the
			// FrequenceAttributes array, since it appears we get
			// all of the former back in a single message.  But just
			// in case ...
			for _, nlbra := range nattrs {
				brattrs, err := netlink.UnmarshalAttributes(nlbra.Data)
				if err != nil {
					return err
				}
				var bra BitrateAttrs
				for _, bra2 := range brattrs {
					switch bra2.Type {
					case unix.NL80211_BITRATE_ATTR_RATE:
						bra.Bitrate = 0.1 * float32(binary.NativeEndian.Uint32(bra2.Data))
					case unix.NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE:
						bra.ShortPreamble = true
					}
				}
				ba.BitrateAttributes = append(ba.BitrateAttributes, bra)
			}

		case unix.NL80211_BAND_ATTR_FREQS:
			nattrs, err := netlink.UnmarshalAttributes(attr.Data)
			if err != nil {
				return err
			}
			for _, nlfa := range nattrs {
				fattrs, err := netlink.UnmarshalAttributes(nlfa.Data)
				if err != nil {
					return err
				}
				var fa FrequencyAttrs
				for _, fa2 := range fattrs {
					switch fa2.Type {
					case unix.NL80211_FREQUENCY_ATTR_FREQ:
						fa.Frequency = int(binary.NativeEndian.Uint32(fa2.Data))
					case unix.NL80211_FREQUENCY_ATTR_DISABLED:
						fa.Disabled = true
					// In 8fe02e167efa8 (3.14), Linux renamed the
					// PASSIVE_SCAN frequency attribute to NO_IR,
					// and deprecated NO_IBSS (4).  It sends both,
					// but we don't need to support old kernels.
					case unix.NL80211_FREQUENCY_ATTR_NO_IR:
						fa.NoIR = true
					case unix.NL80211_FREQUENCY_ATTR_RADAR:
						fa.RadarDetection = true
					case unix.NL80211_FREQUENCY_ATTR_MAX_TX_POWER:
						fa.MaxTxPower = 0.01 * float32(binary.NativeEndian.Uint32(fa2.Data))
					}
				}
				ba.FrequencyAttributes = append(ba.FrequencyAttributes, fa)
			}
		}
	}

	return nil
}

// decodeHTCapabilities parses a 16-bit integer into an HTCapabilities struct
// based on information from an HT Capabilities Info field (NL80211_BAND_ATTR_HT_CAPA).
// Create a new one if nil is passed in, but allow for the struct to have other
// fields already set.
func decodeHTCapabilities(htcap *HTCapabilities, capability uint16) *HTCapabilities {
	if htcap == nil {
		htcap = new(HTCapabilities)
	}

	htcap.RxLDPC = capability&(1<<0) != 0
	htcap.CW40 = capability&(1<<1) != 0
	htcap.HTGreenfield = capability&(1<<4) != 0
	htcap.SGI20 = capability&(1<<5) != 0
	htcap.SGI40 = capability&(1<<6) != 0
	htcap.TxSTBC = capability&(1<<7) != 0
	htcap.RxSTBCStreams = uint8((capability >> 8) & 0x3)
	htcap.HTDelayedBlockAck = capability&(1<<10) != 0
	htcap.LongMaxAMSDULength = capability&(1<<11) != 0
	htcap.DSSSCCKHT40 = capability&(1<<12) != 0
	htcap.FortyMhzIntolerant = capability&(1<<14) != 0
	htcap.LSIGTxOPProtection = capability&(1<<15) != 0

	return htcap
}

// Number of MCS indices in the receive bitmask of an HT Supported MCS Set
// field; the remaining bits of its ten octets are reserved.
const htMCSMaskBits = 77

// decodeHTMCSSet parses the Supported MCS Set field of an HT Capabilities
// element (NL80211_BAND_ATTR_HT_MCS_SET) into an HTCapabilities struct, from
// the raw field already stored in it.  Its multi-octet values are little
// endian, unlike the capability bits nl80211 sends as a native endian integer.
func decodeHTMCSSet(htcap *HTCapabilities) {
	mcs := htcap.SupportedMCS

	// One bit per MCS index, from the least significant bit of the first
	// octet.
	var rx []int
	for i := range htMCSMaskBits {
		if mcs[i/8]&(1<<(i%8)) != 0 {
			rx = append(rx, i)
		}
	}
	htcap.RxMCS = rx

	htcap.RxHighestRate = int(binary.LittleEndian.Uint16(mcs[10:]) & 0x3ff)

	htcap.TxMCSSetDefined = mcs[12]&(1<<0) != 0
	htcap.TxRxMCSSetNotEqual = mcs[12]&(1<<1) != 0
	// The field holds the number of streams minus one.
	htcap.TxMaxSpatialStreams = int((mcs[12]>>2)&0x3) + 1
	htcap.TxUnequalModulation = mcs[12]&(1<<4) != 0
}

// decodeVHTCapabilities parses a 32-bit integer into an VHTCapabilities struct
// based on information from an VHT Capabilities Info field (NL80211_BAND_ATTR_VHT_CAPA).
// Create a new one if nil is passed in, but allow for the struct to have other
// fields already set.
func decodeVHTCapabilities(vhtcap *VHTCapabilities, capability uint32) *VHTCapabilities {
	if vhtcap == nil {
		vhtcap = new(VHTCapabilities)
	}
	switch int(capability & 0x3) {
	case 0:
		vhtcap.MaxMPDULength = 3895
	case 1:
		vhtcap.MaxMPDULength = 7991
	case 2:
		vhtcap.MaxMPDULength = 11454
	}
	vhtcap.VHT160 = capability&(1<<2) != 0
	vhtcap.VHT8080 = capability&(1<<3) != 0
	vhtcap.RXLDPC = capability&(1<<4) != 0
	vhtcap.ShortGI80 = capability&(1<<5) != 0
	vhtcap.ShortGI160 = capability&(1<<6) != 0
	vhtcap.TXSTBC = capability&(1<<7) != 0
	vhtcap.RXSTBC = int((capability >> 8) & 0x7)
	vhtcap.SuBeamFormer = capability&(1<<11) != 0
	vhtcap.SuBeamFormee = capability&(1<<12) != 0
	vhtcap.BFAntenna = int((capability>>13)&0x7) - 1
	vhtcap.SoundingDimension = int((capability >> 16) & 0x7)
	vhtcap.MuBeamformer = capability&(1<<19) != 0
	vhtcap.MuBeamformee = capability&(1<<20) != 0
	vhtcap.VTHTXOPPS = capability&(1<<21) != 0
	vhtcap.HTCVHT = capability&(1<<22) != 0
	vhtcap.MaxAMPDU = 2 ^ (13 + int((capability>>23)&0x2)) - 1
	vhtcap.VHTLinkAdapt = int((capability >> 27) & 0x3)
	vhtcap.RXAntennaPattern = capability&(1<<28) != 0
	vhtcap.TXAntennaPattern = capability&(1<<29) != 0
	vhtcap.ExtendedNSSBW = int((capability >> 30) & 0x7)

	return vhtcap
}

// decodeVHTMCSSet parses the VHT Supported MCS Set field
// (NL80211_BAND_ATTR_VHT_MCS_SET) into a VHTCapabilities struct, from the raw
// field already stored in it.  It holds four little endian values: a map of the
// MCS indices supported for reception and the highest rate for reception,
// followed by the same pair for transmission.
func decodeVHTMCSSet(vhtcap *VHTCapabilities) {
	mcs := vhtcap.SupportedMCS

	vhtcap.RxHighestMCS = decodeVHTMCSMap(binary.LittleEndian.Uint16(mcs[0:]))

	rxHighest := binary.LittleEndian.Uint16(mcs[2:])
	vhtcap.RxHighestRate = int(rxHighest & 0x1fff)
	vhtcap.MaxNSTSTotal = int((rxHighest >> 13) & 0x7)

	vhtcap.TxHighestMCS = decodeVHTMCSMap(binary.LittleEndian.Uint16(mcs[4:]))

	txHighest := binary.LittleEndian.Uint16(mcs[6:])
	vhtcap.TxHighestRate = int(txHighest & 0x1fff)
	vhtcap.ExtendedNSSBWCapable = txHighest&(1<<13) != 0
}

// decodeVHTMCSMap parses a VHT MCS map, which holds two bits per number of
// spatial streams encoding the highest MCS index supported with that number of
// streams.
func decodeVHTMCSMap(m uint16) [8]int {
	var highest [8]int

	for i := range highest {
		switch v := (m >> (2 * i)) & 0x3; v {
		case 3:
			// The device does not support this number of streams.
			highest[i] = -1
		default:
			// 0, 1 and 2 encode MCS 0-7, 0-8 and 0-9.
			highest[i] = 7 + int(v)
		}
	}

	return highest
}

// errInvalidHECapabilities is returned when the kernel reports HE capability
// fields which are too short to decode.
var errInvalidHECapabilities = errors.New("invalid HE capabilities")

const (
	// Lengths in bytes of the fixed-size fields of an HE Capabilities
	// element (802.11ax, 9.4.2.248), and of the HE 6GHz Band Capabilities
	// element (9.4.2.263).
	heMACCapLen   = 6
	hePHYCapLen   = 11
	he6GHzCapaLen = 2

	// Length in bytes of one HE-MCS map, which holds two bits per number of
	// spatial streams.
	heMCSMapLen = 2

	// Number of spatial streams described by an HE-MCS map.
	heMCSMapNSS = 8
)

// errInvalidEHTCapabilities is returned when the kernel reports EHT capability
// fields which are too short to decode.
var errInvalidEHTCapabilities = errors.New("invalid EHT capabilities")

const (
	// Lengths in bytes of the fixed-size fields of an EHT Capabilities
	// element (802.11be, 9.4.2.313).
	ehtMACCapLen = 2
	ehtPHYCapLen = 9

	// Length in bytes of a single EHT-MCS map.
	ehtMCSMapLen = 3

	// Channel width set bits of the first byte of the HE PHY capabilities,
	// which select the maps present in the Supported HE-MCS And NSS Set and
	// Supported EHT-MCS And NSS Set fields.
	hePHYCap040MHzIn2GHz       = 1 << 1
	hePHYCap040MHz80MHzIn5GHz  = 1 << 2
	hePHYCap0160MHzIn5GHz      = 1 << 3
	hePHYCap080Plus80MHzIn5GHz = 1 << 4

	// 320MHz support in the first byte of the EHT PHY capabilities, which
	// adds a further map to the Supported EHT-MCS And NSS Set field.
	ehtPHYCap0320MHzIn6GHz = 1 << 1
)

// parseBandIftypeData parses the per-interface type data of a band
// (NL80211_BAND_ATTR_IFTYPE_DATA) into the HE and EHT capabilities it
// advertises, one element for each set of interface types which share the same
// capabilities.  Sets which advertise no capabilities of a given generation are
// skipped, so either result is nil for a band which does not support it.
func parseBandIftypeData(b []byte) ([]HECapabilities, []EHTCapabilities, error) {
	iftypes, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, nil, err
	}

	var (
		hecaps  []HECapabilities
		ehtcaps []EHTCapabilities
	)

	for _, iftype := range iftypes {
		attrs, err := netlink.UnmarshalAttributes(iftype.Data)
		if err != nil {
			return nil, nil, err
		}

		var (
			types []InterfaceType

			hecap  HECapabilities
			ehtcap EHTCapabilities

			hasHE  bool
			hasEHT bool

			// Retained to decode the Supported HE-MCS And NSS Set
			// and Supported EHT-MCS And NSS Set fields, whose
			// layouts depend on them.
			hePHYCap  []byte
			ehtPHYCap []byte
		)

		for _, a := range attrs {
			switch a.Type {
			case unix.NL80211_BAND_IFTYPE_ATTR_IFTYPES:
				// This contains nested attributes with no data;
				// the data we care about is the type.
				nattrs, err := netlink.UnmarshalAttributes(a.Data)
				if err != nil {
					return nil, nil, err
				}
				for _, t := range nattrs {
					types = append(types, InterfaceType(t.Type))
				}

			case unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC:
				if len(a.Data) < heMACCapLen {
					return nil, nil, errInvalidHECapabilities
				}
				decodeHEMACCapabilities(&hecap, a.Data)
				hasHE = true

			case unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY:
				if len(a.Data) < hePHYCapLen {
					return nil, nil, errInvalidHECapabilities
				}
				decodeHEPHYCapabilities(&hecap, a.Data)
				hePHYCap = a.Data
				hasHE = true

			case unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET:
				hecap.SupportedMCS = slices.Clone(a.Data)

			case unix.NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE:
				hecap.PPEThresholds = slices.Clone(a.Data)

			case unix.NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA:
				if len(a.Data) < he6GHzCapaLen {
					return nil, nil, errInvalidHECapabilities
				}
				hecap.HE6GHzCapabilities = decodeHE6GHzCapabilities(
					binary.LittleEndian.Uint16(a.Data),
				)

			case unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC:
				if len(a.Data) < ehtMACCapLen {
					return nil, nil, errInvalidEHTCapabilities
				}
				decodeEHTMACCapabilities(&ehtcap, a.Data)
				hasEHT = true

			case unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY:
				if len(a.Data) < ehtPHYCapLen {
					return nil, nil, errInvalidEHTCapabilities
				}
				decodeEHTPHYCapabilities(&ehtcap, a.Data)
				ehtPHYCap = a.Data
				hasEHT = true

			case unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET:
				ehtcap.SupportedMCS = slices.Clone(a.Data)

			case unix.NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE:
				ehtcap.PPEThresholds = slices.Clone(a.Data)
			}
		}

		if hasHE {
			hecap.InterfaceTypes = slices.Clone(types)
			hecap.SupportedMCSSets = decodeHEMCSNSSSets(hecap.SupportedMCS, hePHYCap)

			// The kernel always sends the thresholds, as a
			// fixed-size buffer, so drop them unless the device
			// says they hold anything.
			if !hecap.PPEThresholdsPresent {
				hecap.PPEThresholds = nil
			}

			hecaps = append(hecaps, hecap)
		}

		if hasEHT {
			ehtcap.InterfaceTypes = slices.Clone(types)

			// The kernel sends a zero length attribute rather than
			// omitting it, so normalise the empty case to nil.
			if !ehtcap.PPEThresholdsPresent {
				ehtcap.PPEThresholds = nil
			}

			ehtcap.SupportedMCSSets = decodeEHTMCSNSSSets(
				ehtcap.SupportedMCS,
				hePHYCap,
				ehtPHYCap,
				isAPInterfaceType(types),
			)
			ehtcaps = append(ehtcaps, ehtcap)
		}
	}

	return hecaps, ehtcaps, nil
}

// isAPInterfaceType reports whether any of types transmits as an access point,
// which changes the layout of the Supported EHT-MCS And NSS Set field.
func isAPInterfaceType(types []InterfaceType) bool {
	return slices.ContainsFunc(
		types, func(t InterfaceType) bool {
			return t == InterfaceTypeAP || t == InterfaceTypeP2PGroupOwner
		},
	)
}

// decodeHEMACCapabilities parses the six byte HE MAC Capabilities Information
// field (NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC) into an HECapabilities struct.
// Several of its subfields are split across two bytes.
func decodeHEMACCapabilities(hecap *HECapabilities, mac []byte) {
	hecap.HTCHE = mac[0]&(1<<0) != 0
	hecap.TWTRequester = mac[0]&(1<<1) != 0
	hecap.TWTResponder = mac[0]&(1<<2) != 0
	hecap.DynamicFragmentation = int((mac[0] >> 3) & 0x3)
	hecap.MaxFragmentedMSDUs = int((mac[0] >> 5) & 0x7)

	switch mac[1] & 0x3 {
	case 1:
		hecap.MinFragmentSize = 128
	case 2:
		hecap.MinFragmentSize = 256
	case 3:
		hecap.MinFragmentSize = 512
	}

	switch (mac[1] >> 2) & 0x3 {
	case 1:
		hecap.TriggerFrameMACPaddingDuration = 8
	case 2:
		hecap.TriggerFrameMACPaddingDuration = 16
	}

	hecap.MultiTIDAggregationRx = int((mac[1] >> 4) & 0x7)
	hecap.LinkAdaptation = int((mac[1]>>7)&0x1 | (mac[2]&0x1)<<1)

	hecap.AllAck = mac[2]&(1<<1) != 0
	hecap.TRS = mac[2]&(1<<2) != 0
	hecap.BSR = mac[2]&(1<<3) != 0
	hecap.BroadcastTWT = mac[2]&(1<<4) != 0
	hecap.BA32BitBitmap = mac[2]&(1<<5) != 0
	hecap.MUCascading = mac[2]&(1<<6) != 0
	hecap.AckEnabledAggregation = mac[2]&(1<<7) != 0

	hecap.OMControl = mac[3]&(1<<1) != 0
	hecap.OFDMARA = mac[3]&(1<<2) != 0
	hecap.MaxAMPDULengthExponentExt = int((mac[3] >> 3) & 0x3)
	hecap.AMSDUFragmentation = mac[3]&(1<<5) != 0
	hecap.FlexibleTWTScheduling = mac[3]&(1<<6) != 0
	hecap.RxControlFrameToMultiBSS = mac[3]&(1<<7) != 0

	hecap.BSRPBQRPAMPDUAggregation = mac[4]&(1<<0) != 0
	hecap.QTP = mac[4]&(1<<1) != 0
	hecap.BQR = mac[4]&(1<<2) != 0
	hecap.PSRResponder = mac[4]&(1<<3) != 0
	hecap.NDPFeedbackReport = mac[4]&(1<<4) != 0
	hecap.OPS = mac[4]&(1<<5) != 0
	hecap.AMSDUInAMPDU = mac[4]&(1<<6) != 0
	hecap.MultiTIDAggregationTx = int((mac[4]>>7)&0x1 | (mac[5]&0x3)<<1)

	hecap.SubchannelSelectiveTransmission = mac[5]&(1<<2) != 0
	hecap.UL2x996ToneRU = mac[5]&(1<<3) != 0
	hecap.OMControlULMUDataDisableRx = mac[5]&(1<<4) != 0
	hecap.DynamicSMPowerSave = mac[5]&(1<<5) != 0
	hecap.PuncturedSounding = mac[5]&(1<<6) != 0
	hecap.HTVHTTriggerFrameRx = mac[5]&(1<<7) != 0
}

// decodeHEPHYCapabilities parses the eleven byte HE PHY Capabilities
// Information field (NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY) into an
// HECapabilities struct.
func decodeHEPHYCapabilities(hecap *HECapabilities, phy []byte) {
	hecap.Support40MHzIn2GHz = phy[0]&hePHYCap040MHzIn2GHz != 0
	hecap.Support40MHz80MHzIn5GHz = phy[0]&hePHYCap040MHz80MHzIn5GHz != 0
	hecap.Support160MHzIn5GHz = phy[0]&hePHYCap0160MHzIn5GHz != 0
	hecap.Support80Plus80MHzIn5GHz = phy[0]&hePHYCap080Plus80MHzIn5GHz != 0
	hecap.Support242ToneRUIn2GHz = phy[0]&(1<<5) != 0
	hecap.Support242ToneRUIn5GHz = phy[0]&(1<<6) != 0

	hecap.PuncturedPreambleRx = int(phy[1] & 0xf)
	hecap.DeviceClassA = phy[1]&(1<<4) != 0
	hecap.LDPCCodingInPayload = phy[1]&(1<<5) != 0
	hecap.HESUPPDU1xHELTFAnd08usGI = phy[1]&(1<<6) != 0
	hecap.MidambleRxMaxNSTS = int((phy[1]>>7)&0x1 | (phy[2]&0x1)<<1)

	hecap.NDP4xHELTFAnd32usGI = phy[2]&(1<<1) != 0
	hecap.STBCTx80MHz = phy[2]&(1<<2) != 0
	hecap.STBCRx80MHz = phy[2]&(1<<3) != 0
	hecap.DopplerTx = phy[2]&(1<<4) != 0
	hecap.DopplerRx = phy[2]&(1<<5) != 0
	hecap.FullBandwidthULMUMIMO = phy[2]&(1<<6) != 0
	hecap.PartialBandwidthULMUMIMO = phy[2]&(1<<7) != 0

	hecap.DCMMaxConstellationTx = int(phy[3] & 0x3)
	hecap.DCMMaxNSSTx = int((phy[3] >> 2) & 0x1)
	hecap.DCMMaxConstellationRx = int((phy[3] >> 3) & 0x3)
	hecap.DCMMaxNSSRx = int((phy[3] >> 5) & 0x1)
	hecap.RxPartialBandwidthSUIn20MHzMU = phy[3]&(1<<6) != 0
	hecap.SUBeamformer = phy[3]&(1<<7) != 0

	hecap.SUBeamformee = phy[4]&(1<<0) != 0
	hecap.MUBeamformer = phy[4]&(1<<1) != 0
	hecap.BeamformeeSTS80MHz = int((phy[4] >> 2) & 0x7)
	hecap.BeamformeeSTSAbove80MHz = int((phy[4] >> 5) & 0x7)

	hecap.SoundingDimensions80MHz = int(phy[5] & 0x7)
	hecap.SoundingDimensionsAbove80MHz = int((phy[5] >> 3) & 0x7)
	hecap.NG16SUFeedback = phy[5]&(1<<6) != 0
	hecap.NG16MUFeedback = phy[5]&(1<<7) != 0

	hecap.Codebook42SUFeedback = phy[6]&(1<<0) != 0
	hecap.Codebook75MUFeedback = phy[6]&(1<<1) != 0
	hecap.TriggeredSUBeamformingFeedback = phy[6]&(1<<2) != 0
	hecap.TriggeredMUBeamformingPartialBWFeedback = phy[6]&(1<<3) != 0
	hecap.TriggeredCQIFeedback = phy[6]&(1<<4) != 0
	hecap.PartialBandwidthExtendedRange = phy[6]&(1<<5) != 0
	hecap.PartialBandwidthDLMUMIMO = phy[6]&(1<<6) != 0
	hecap.PPEThresholdsPresent = phy[6]&(1<<7) != 0

	hecap.PSRBasedSR = phy[7]&(1<<0) != 0
	hecap.PowerBoostFactor = phy[7]&(1<<1) != 0
	hecap.HESUMUPPDU4xHELTFAnd08usGI = phy[7]&(1<<2) != 0
	hecap.MaxNc = int((phy[7] >> 3) & 0x7)
	hecap.STBCTxAbove80MHz = phy[7]&(1<<6) != 0
	hecap.STBCRxAbove80MHz = phy[7]&(1<<7) != 0

	hecap.HEERSUPPDU4xHELTFAnd08usGI = phy[8]&(1<<0) != 0
	hecap.Support20MHzIn40MHzHEPPDUIn2GHz = phy[8]&(1<<1) != 0
	hecap.Support20MHzIn160MHzHEPPDU = phy[8]&(1<<2) != 0
	hecap.Support80MHzIn160MHzHEPPDU = phy[8]&(1<<3) != 0
	hecap.HEERSUPPDU1xHELTFAnd08usGI = phy[8]&(1<<4) != 0
	hecap.MidambleRx2xAnd1xHELTF = phy[8]&(1<<5) != 0
	hecap.DCMMaxRU = int((phy[8] >> 6) & 0x3)

	hecap.LongerThan16HESIGBOFDMSymbols = phy[9]&(1<<0) != 0
	hecap.NonTriggeredCQIFeedback = phy[9]&(1<<1) != 0
	hecap.Tx1024QAMLess242ToneRU = phy[9]&(1<<2) != 0
	hecap.Rx1024QAMLess242ToneRU = phy[9]&(1<<3) != 0
	hecap.RxFullBWSUUsingMUCompressedSIGB = phy[9]&(1<<4) != 0
	hecap.RxFullBWSUUsingMUNonCompressedSIGB = phy[9]&(1<<5) != 0

	switch (phy[9] >> 6) & 0x3 {
	case 1:
		hecap.NominalPacketPadding = 8
	case 2:
		hecap.NominalPacketPadding = 16
	}

	hecap.HEMUM1RUMaxLTF = phy[10]&(1<<0) != 0
}

// decodeHEMCSNSSSets parses the Supported HE-MCS And NSS Set field
// (NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET), which holds a pair of receive and
// transmit maps for each channel width advertised in the HE PHY capabilities.
func decodeHEMCSNSSSets(mcs, hePHYCap []byte) []HEMCSNSSSet {
	if len(mcs) == 0 || len(hePHYCap) == 0 {
		return nil
	}

	// The maps appear in this order, and only for the channel widths the
	// device supports.
	widths := []struct {
		width ChannelWidth
		capa  byte
	}{
		{ChannelWidth80, hePHYCap040MHzIn2GHz | hePHYCap040MHz80MHzIn5GHz},
		{ChannelWidth160, hePHYCap0160MHzIn5GHz},
		{ChannelWidth80P80, hePHYCap080Plus80MHzIn5GHz},
	}

	var sets []HEMCSNSSSet
	for i, w := range widths {
		// Each width occupies a receive and a transmit map, whether or
		// not the device supports it.
		off := i * 2 * heMCSMapLen
		if len(mcs) < off+2*heMCSMapLen {
			break
		}

		if hePHYCap[0]&w.capa == 0 {
			continue
		}

		sets = append(
			sets, HEMCSNSSSet{
				Width:        w.width,
				RxHighestMCS: decodeHEMCSMap(mcs[off:]),
				TxHighestMCS: decodeHEMCSMap(mcs[off+heMCSMapLen:]),
			},
		)
	}

	// A device which supports no channel width beyond 20MHz still reports
	// the first pair of maps, which is mandatory and describes its 20MHz
	// operation.
	if len(sets) == 0 && len(mcs) >= 2*heMCSMapLen {
		return []HEMCSNSSSet{{
			Width:        ChannelWidth20,
			RxHighestMCS: decodeHEMCSMap(mcs),
			TxHighestMCS: decodeHEMCSMap(mcs[heMCSMapLen:]),
		}}
	}

	return sets
}

// decodeHEMCSMap parses a single HE-MCS map, which holds two bits per number of
// spatial streams encoding the highest MCS index supported with that number of
// streams.
func decodeHEMCSMap(mcs []byte) [heMCSMapNSS]int {
	var highest [heMCSMapNSS]int

	m := binary.LittleEndian.Uint16(mcs)
	for i := range highest {
		switch v := (m >> (2 * i)) & 0x3; v {
		case 3:
			// The device does not support this number of streams.
			highest[i] = -1
		default:
			// 0, 1 and 2 encode MCS 0-7, 0-9 and 0-11.
			highest[i] = 7 + 2*int(v)
		}
	}

	return highest
}

// decodeHE6GHzCapabilities parses the two byte HE 6GHz Band Capabilities
// element (NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA), which carries the attributes
// a device would otherwise advertise in its HT and VHT capabilities.
func decodeHE6GHzCapabilities(capa uint16) *HE6GHzCapabilities {
	he6ghz := new(HE6GHzCapabilities)

	if spacing := capa & 0x7; spacing > 0 {
		he6ghz.MinMPDUStartSpacing = (1 << (spacing - 1)) * time.Microsecond / 4
	}

	he6ghz.MaxRxAMPDULength = (1 << (13 + (capa>>3)&0x7)) - 1

	switch (capa >> 6) & 0x3 {
	case 0:
		he6ghz.MaxMPDULength = 3895
	case 1:
		he6ghz.MaxMPDULength = 7991
	case 2:
		he6ghz.MaxMPDULength = 11454
	}

	he6ghz.SMPowerSave = int((capa >> 9) & 0x3)
	he6ghz.RDResponder = capa&(1<<11) != 0
	he6ghz.RXAntennaPattern = capa&(1<<12) != 0
	he6ghz.TXAntennaPattern = capa&(1<<13) != 0

	return he6ghz
}

// decodeEHTMACCapabilities parses the two byte EHT MAC Capabilities Information
// field (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC) into an EHTCapabilities struct.
func decodeEHTMACCapabilities(ehtcap *EHTCapabilities, mac []byte) {
	ehtcap.EPCSPriorityAccess = mac[0]&(1<<0) != 0
	ehtcap.OMControl = mac[0]&(1<<1) != 0
	ehtcap.TriggeredTXOPSharingMode1 = mac[0]&(1<<2) != 0
	ehtcap.TriggeredTXOPSharingMode2 = mac[0]&(1<<3) != 0
	ehtcap.RestrictedTWT = mac[0]&(1<<4) != 0
	ehtcap.SCSTrafficDescription = mac[0]&(1<<5) != 0

	switch (mac[0] >> 6) & 0x3 {
	case 0:
		ehtcap.MaxMPDULength = 3895
	case 1:
		ehtcap.MaxMPDULength = 7991
	case 2:
		ehtcap.MaxMPDULength = 11454
	}

	ehtcap.MaxAMPDULengthExponentExt = int(mac[1] & 0x1)
	ehtcap.TRS = mac[1]&(1<<1) != 0
	ehtcap.TXOPReturn = mac[1]&(1<<2) != 0
	ehtcap.TwoBQRs = mac[1]&(1<<3) != 0
	ehtcap.LinkAdaptation = int((mac[1] >> 4) & 0x3)
	ehtcap.UnsolicitedEPCSPriorityAccess = mac[1]&(1<<6) != 0
}

// decodeEHTPHYCapabilities parses the nine byte EHT PHY Capabilities
// Information field (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY) into an
// EHTCapabilities struct.  Several of its subfields are split across two bytes.
func decodeEHTPHYCapabilities(ehtcap *EHTCapabilities, phy []byte) {
	ehtcap.Support320MHzIn6GHz = phy[0]&(1<<1) != 0
	ehtcap.Support242ToneRUWiderThan20MHz = phy[0]&(1<<2) != 0
	ehtcap.NDP4xEHTLTFAnd32usGI = phy[0]&(1<<3) != 0
	ehtcap.PartialBandwidthULMUMIMO = phy[0]&(1<<4) != 0
	ehtcap.SUBeamformer = phy[0]&(1<<5) != 0
	ehtcap.SUBeamformee = phy[0]&(1<<6) != 0

	ehtcap.BeamformeeSS80MHz = int((phy[0]>>7)&0x1 | (phy[1]&0x3)<<1)
	ehtcap.BeamformeeSS160MHz = int((phy[1] >> 2) & 0x7)
	ehtcap.BeamformeeSS320MHz = int((phy[1] >> 5) & 0x7)

	ehtcap.SoundingDimensions80MHz = int(phy[2] & 0x7)
	ehtcap.SoundingDimensions160MHz = int((phy[2] >> 3) & 0x7)
	ehtcap.SoundingDimensions320MHz = int((phy[2]>>6)&0x3 | (phy[3]&0x1)<<2)

	ehtcap.NG16SUFeedback = phy[3]&(1<<1) != 0
	ehtcap.NG16MUFeedback = phy[3]&(1<<2) != 0
	ehtcap.Codebook42SUFeedback = phy[3]&(1<<3) != 0
	ehtcap.Codebook75MUFeedback = phy[3]&(1<<4) != 0
	ehtcap.TriggeredSUBeamformingFeedback = phy[3]&(1<<5) != 0
	ehtcap.TriggeredMUBeamformingPartialBWFeedback = phy[3]&(1<<6) != 0
	ehtcap.TriggeredCQIFeedback = phy[3]&(1<<7) != 0

	ehtcap.PartialBandwidthDLMUMIMO = phy[4]&(1<<0) != 0
	ehtcap.PSRBasedSR = phy[4]&(1<<1) != 0
	ehtcap.PowerBoostFactor = phy[4]&(1<<2) != 0
	ehtcap.EHTMUPPDU4xEHTLTFAnd08usGI = phy[4]&(1<<3) != 0
	ehtcap.MaxNc = int((phy[4] >> 4) & 0xf)

	ehtcap.NonTriggeredCQIFeedback = phy[5]&(1<<0) != 0
	ehtcap.TxLess242ToneRU = phy[5]&(1<<1) != 0
	ehtcap.RxLess242ToneRU = phy[5]&(1<<2) != 0
	ehtcap.PPEThresholdsPresent = phy[5]&(1<<3) != 0

	switch (phy[5] >> 4) & 0x3 {
	case 0:
		ehtcap.CommonNominalPacketPadding = 0
	case 1:
		ehtcap.CommonNominalPacketPadding = 8
	case 2:
		ehtcap.CommonNominalPacketPadding = 16
	case 3:
		ehtcap.CommonNominalPacketPadding = 20
	}

	ehtcap.MaxSupportedEHTLTFs = int((phy[5]>>6)&0x3 | (phy[6]&0x7)<<2)
	ehtcap.MCS15Support = int((phy[6] >> 3) & 0xf)
	ehtcap.EHTDupIn6GHz = phy[6]&(1<<7) != 0

	ehtcap.Support20MHzRxNDPWiderBandwidth = phy[7]&(1<<0) != 0
	ehtcap.NonOFDMAULMUMIMO80MHz = phy[7]&(1<<1) != 0
	ehtcap.NonOFDMAULMUMIMO160MHz = phy[7]&(1<<2) != 0
	ehtcap.NonOFDMAULMUMIMO320MHz = phy[7]&(1<<3) != 0
	ehtcap.MUBeamformer80MHz = phy[7]&(1<<4) != 0
	ehtcap.MUBeamformer160MHz = phy[7]&(1<<5) != 0
	ehtcap.MUBeamformer320MHz = phy[7]&(1<<6) != 0
	ehtcap.TBSoundingFeedbackRateLimit = phy[7]&(1<<7) != 0

	ehtcap.Rx1024QAMWiderBandwidthDLOFDMA = phy[8]&(1<<0) != 0
	ehtcap.Rx4096QAMWiderBandwidthDLOFDMA = phy[8]&(1<<1) != 0
}

// decodeEHTMCSNSSSets parses the Supported EHT-MCS And NSS Set field
// (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET).  Which maps the field holds, and
// therefore how long it is, depends on the channel widths advertised in the HE
// PHY capabilities, on 320MHz support in the EHT PHY capabilities, and on
// whether the interface types transmit as an access point.  See
// ieee80211_eht_mcs_nss_size in the Linux kernel's ieee80211.h.
func decodeEHTMCSNSSSets(mcs, hePHYCap, ehtPHYCap []byte, isAP bool) []EHTMCSNSSSet {
	// Both capability fields are needed to make sense of the maps.
	if len(mcs) == 0 || len(hePHYCap) == 0 || len(ehtPHYCap) == 0 {
		return nil
	}

	// In the 2.4GHz band a device which supports 40MHz channels reports a
	// single map, and the remaining channel width bits are reserved.
	if hePHYCap[0]&hePHYCap040MHzIn2GHz != 0 {
		return decodeEHTMCSMaps(mcs, ChannelWidth80)
	}

	var widths []ChannelWidth
	if hePHYCap[0]&hePHYCap040MHz80MHzIn5GHz != 0 {
		widths = append(widths, ChannelWidth80)
	}
	if hePHYCap[0]&hePHYCap0160MHzIn5GHz != 0 {
		widths = append(widths, ChannelWidth160)
	}
	if ehtPHYCap[0]&ehtPHYCap0320MHzIn6GHz != 0 {
		widths = append(widths, ChannelWidth320)
	}

	if len(widths) > 0 {
		return decodeEHTMCSMaps(mcs, widths...)
	}

	// No channel width beyond 20MHz: an access point still reports a single
	// map, while a station reports the wider map for 20MHz-only stations.
	if isAP {
		return decodeEHTMCSMaps(mcs, ChannelWidth80)
	}

	return []EHTMCSNSSSet{
		{
			Width:     ChannelWidth20,
			MCSRanges: decodeEHTMCSMap(mcs, [][2]int{{0, 7}, {8, 9}, {10, 11}, {12, 13}}),
		},
	}
}

// decodeEHTMCSMaps parses one three byte EHT-MCS map per channel width in
// widths, in the order the maps appear in the Supported EHT-MCS And NSS Set
// field.
func decodeEHTMCSMaps(mcs []byte, widths ...ChannelWidth) []EHTMCSNSSSet {
	ranges := [][2]int{{0, 9}, {10, 11}, {12, 13}}

	sets := make([]EHTMCSNSSSet, 0, len(widths))
	for _, w := range widths {
		if len(mcs) < ehtMCSMapLen {
			// The kernel reported a shorter field than the
			// capabilities call for; decode what is there.
			break
		}

		sets = append(
			sets, EHTMCSNSSSet{
				Width:     w,
				MCSRanges: decodeEHTMCSMap(mcs[:ehtMCSMapLen], ranges),
			},
		)
		mcs = mcs[ehtMCSMapLen:]
	}

	if len(sets) == 0 {
		return nil
	}

	return sets
}

// decodeEHTMCSMap parses a single EHT-MCS map, which holds one byte per range
// of MCS indices: the low nibble is the maximum number of spatial streams for
// reception, and the high nibble the maximum number for transmission.
func decodeEHTMCSMap(mcs []byte, ranges [][2]int) []EHTMCSNSS {
	n := min(len(mcs), len(ranges))

	nss := make([]EHTMCSNSS, 0, n)
	for i := range n {
		nss = append(
			nss, EHTMCSNSS{
				MinMCS:   ranges[i][0],
				MaxMCS:   ranges[i][1],
				RxMaxNSS: int(mcs[i] & 0xf),
				TxMaxNSS: int(mcs[i] >> 4),
			},
		)
	}

	return nss
}

// parseAttributes parses netlink attributes into a BSS's fields.
func (b *BSS) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_BSS_BSSID:
			b.BSSID = net.HardwareAddr(a.Data)
		case unix.NL80211_BSS_FREQUENCY:
			b.Frequency = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_BSS_BEACON_INTERVAL:
			// Raw value is in "Time Units (TU)".  See:
			// https://en.wikipedia.org/wiki/Beacon_frame
			b.BeaconInterval = time.Duration(binary.NativeEndian.Uint16(a.Data)) * 1024 * time.Microsecond
		case unix.NL80211_BSS_SEEN_MS_AGO:
			// * @NL80211_BSS_SEEN_MS_AGO: age of this BSS entry in ms
			b.LastSeen = time.Duration(binary.NativeEndian.Uint32(a.Data)) * time.Millisecond
		case unix.NL80211_BSS_STATUS:
			// NOTE: BSSStatus copies the ordering of nl80211's BSS status
			// constants.  This may not be the case on other operating systems.
			b.Status = BSSStatus(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_BSS_SIGNAL_MBM:
			// * @NL80211_BSS_SIGNAL_MBM: signal strength in mBm (100*dBm)
			b.Signal = int32(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_BSS_SIGNAL_UNSPEC:
			// * @NL80211_BSS_SIGNAL_UNSPEC: signal strength in unspecified units (usually percent)
			b.SignalUnspecified = binary.NativeEndian.Uint32(a.Data)
		case unix.NL80211_BSS_INFORMATION_ELEMENTS:
			ies, err := parseIEs(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more IEs if they end up being generally useful
			for _, ie := range ies {
				switch ie.ID {
				case ieSSID:
					b.SSID = decodeSSID(ie.Data)
				case ieBSSLoad:
					Bssload, err := decodeBSSLoad(ie.Data)
					if err != nil {
						continue // This IE is malformed
					}
					b.Load = *Bssload
				case ieRSN:
					rsnInfo, err := decodeRSN(ie.Data)
					if err != nil {
						continue // This IE is malformed
					}
					b.RSN = *rsnInfo
				}
			}
		}
	}

	return nil
}

// ParseStationInfo parses StationInfo attributes from a byte slice of
// netlink attributes.
func ParseStationInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info StationInfo
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_IFINDEX:
			info.InterfaceIndex = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_ATTR_MAC:
			info.HardwareAddr = net.HardwareAddr(a.Data)
		case unix.NL80211_ATTR_STA_INFO:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if err := (&info).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			// Parsed the necessary data.
			return &info, nil
		}
	}

	// No station info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a StationInfo's fields.
func (info *StationInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_STA_INFO_CONNECTED_TIME:
			// Though nl80211 does not specify, this value appears to be in seconds:
			// * @NL80211_STA_INFO_CONNECTED_TIME: time since the station is last connected
			info.Connected = time.Duration(binary.NativeEndian.Uint32(a.Data)) * time.Second
		case unix.NL80211_STA_INFO_INACTIVE_TIME:
			// * @NL80211_STA_INFO_INACTIVE_TIME: time since last activity (u32, msecs)
			info.Inactive = time.Duration(binary.NativeEndian.Uint32(a.Data)) * time.Millisecond
		case unix.NL80211_STA_INFO_RX_BYTES64:
			info.ReceivedBytes = int(binary.NativeEndian.Uint64(a.Data))
		case unix.NL80211_STA_INFO_TX_BYTES64:
			info.TransmittedBytes = int(binary.NativeEndian.Uint64(a.Data))
		case unix.NL80211_STA_INFO_SIGNAL:
			//  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
			// Should just be cast to int8, see code here: https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git/tree/station.c#n378
			info.Signal = int(int8(a.Data[0]))
		case unix.NL80211_STA_INFO_SIGNAL_AVG:
			info.SignalAverage = int(int8(a.Data[0]))
		case unix.NL80211_STA_INFO_RX_PACKETS:
			info.ReceivedPackets = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_PACKETS:
			info.TransmittedPackets = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_RETRIES:
			info.TransmitRetries = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_FAILED:
			info.TransmitFailed = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_STA_INFO_BEACON_LOSS:
			info.BeaconLoss = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_STA_INFO_RX_BITRATE, unix.NL80211_STA_INFO_TX_BITRATE:
			rate, err := parseRateInfo(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more statistics if they end up being
			// generally useful
			switch a.Type {
			case unix.NL80211_STA_INFO_RX_BITRATE:
				info.ReceiveBitrate = rate.Bitrate
				info.ReceiveRateInfo = rate
			case unix.NL80211_STA_INFO_TX_BITRATE:
				info.TransmitBitrate = rate.Bitrate
				info.TransmitRateInfo = rate
			}
		}

		// Only use 32-bit counters if the 64-bit counters are not present.
		// If the 64-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.ReceivedBytes == 0 && a.Type == unix.NL80211_STA_INFO_RX_BYTES {
			info.ReceivedBytes = int(binary.NativeEndian.Uint32(a.Data))
		}
		if info.TransmittedBytes == 0 && a.Type == unix.NL80211_STA_INFO_TX_BYTES {
			info.TransmittedBytes = int(binary.NativeEndian.Uint32(a.Data))
		}
	}

	return nil
}

// parseRateInfo parses a rateInfo from netlink attributes.
func parseRateInfo(b []byte) (RateInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return RateInfo{}, err
	}

	var rateinfo RateInfo
	// initialize with unknown values
	htModulationInfo := HTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: -1, NSS: -1}}
	vhtModulationInfo := VHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: -1, NSS: -1}}
	heModulationInfo := HEModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: -1, NSS: -1}}
	ehtModulationInfo := EHTModulationInfo{BaseModulationInfo: BaseModulationInfo{MCS: -1, NSS: -1}}

	// re-use Channel Width type from Interface, even though we classify via NL80211_RATE_INFO_*
	var channelWidth ChannelWidth
	channelWidth = ChannelWidth20 // default to 20 MHz if not specified

	for _, a := range attrs {
		// see iw's station.c for reference implementation
		// serach for parse_bitrate(struct nlattr *bitrate_attr, char *buf, int buflen)
		// at the moment of implementation iw v6.17 was used:
		// https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git/tree/station.c?h=v6.17#n199
		switch a.Type {
		case unix.NL80211_RATE_INFO_BITRATE32:
			rateinfo.Bitrate = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_RATE_INFO_BITRATE:
			// Only use 16-bit counters if the 32-bit counters are not present.
			// If the 32-bit counters appear later in the slice, they will overwrite
			// these values.
			if rateinfo.Bitrate == 0 {
				rateinfo.Bitrate = int(binary.NativeEndian.Uint16(a.Data))
			}
		case unix.NL80211_RATE_INFO_MCS:
			htModulationInfo.HTMCS = int(a.Data[0])
			htModulationInfo.MCS = htModulationInfo.HTMCS % 8
			htModulationInfo.NSS = (htModulationInfo.HTMCS / 8) + 1
		case unix.NL80211_RATE_INFO_VHT_MCS:
			vhtModulationInfo.MCS = int(a.Data[0])
		case unix.NL80211_RATE_INFO_40_MHZ_WIDTH:
			channelWidth = ChannelWidth40
		case unix.NL80211_RATE_INFO_80_MHZ_WIDTH:
			channelWidth = ChannelWidth80
		case unix.NL80211_RATE_INFO_80P80_MHZ_WIDTH:
			channelWidth = ChannelWidth80P80
		case unix.NL80211_RATE_INFO_160_MHZ_WIDTH:
			channelWidth = ChannelWidth160
		case unix.NL80211_RATE_INFO_320_MHZ_WIDTH:
			channelWidth = ChannelWidth320
		case unix.NL80211_RATE_INFO_1_MHZ_WIDTH:
			channelWidth = ChannelWidth1
		case unix.NL80211_RATE_INFO_2_MHZ_WIDTH:
			channelWidth = ChannelWidth2
		case unix.NL80211_RATE_INFO_4_MHZ_WIDTH:
			channelWidth = ChannelWidth4
		case unix.NL80211_RATE_INFO_8_MHZ_WIDTH:
			channelWidth = ChannelWidth8
		case unix.NL80211_RATE_INFO_16_MHZ_WIDTH:
			channelWidth = ChannelWidth16
		case unix.NL80211_RATE_INFO_SHORT_GI:
			htModulationInfo.ShortGI = true
			vhtModulationInfo.ShortGI = true
		case unix.NL80211_RATE_INFO_VHT_NSS:
			vhtModulationInfo.NSS = int(a.Data[0])
		case unix.NL80211_RATE_INFO_HE_MCS:
			heModulationInfo.MCS = int(a.Data[0])
		case unix.NL80211_RATE_INFO_HE_NSS:
			heModulationInfo.NSS = int(a.Data[0])
		case unix.NL80211_RATE_INFO_HE_GI:
			heModulationInfo.GI = int(a.Data[0])
		case unix.NL80211_RATE_INFO_HE_DCM:
			heModulationInfo.DCM = int(a.Data[0])
		case unix.NL80211_RATE_INFO_HE_RU_ALLOC:
			heModulationInfo.RUAlloc = int(a.Data[0])
		case unix.NL80211_RATE_INFO_EHT_MCS:
			ehtModulationInfo.MCS = int(a.Data[0])
		case unix.NL80211_RATE_INFO_EHT_NSS:
			ehtModulationInfo.NSS = int(a.Data[0])
		case unix.NL80211_RATE_INFO_EHT_GI:
			ehtModulationInfo.GI = int(a.Data[0])
		case unix.NL80211_RATE_INFO_EHT_RU_ALLOC:
			ehtModulationInfo.RUAlloc = int(a.Data[0])
		}
	}

	// Assign modulation info based on what was found
	// highest WiFi standard with valid MCS found determines modulation type
	switch {
	case ehtModulationInfo.MCS != -1:
		rateinfo.ModulationType = RateModulationInfoTypeEHT
		rateinfo.Modulation = ehtModulationInfo
	case heModulationInfo.MCS != -1:
		rateinfo.ModulationType = RateModulationInfoTypeHE
		rateinfo.Modulation = heModulationInfo
	case vhtModulationInfo.MCS != -1:
		rateinfo.ModulationType = RateModulationInfoTypeVHT
		rateinfo.Modulation = vhtModulationInfo
	case htModulationInfo.MCS != -1:
		rateinfo.ModulationType = RateModulationInfoTypeHT
		rateinfo.Modulation = htModulationInfo
	default:
		// On legacy Networks the modulation info is not provided, so we set the type to legacy and the modulation info to nil
		rateinfo.ModulationType = RateModulationInfoTypeLegacy
		rateinfo.Modulation = nil
	}

	rateinfo.ChannelWidth = channelWidth
	if rateinfo.ChannelWidth == ChannelWidth20 {
		// For legacy networks, 20MHzNoHT is the default channel width, so we set it to that if no channel width was provided
		rateinfo.ChannelWidth = ChannelWidth20NoHT
	}

	// Scale bitrate to bits/second as base unit instead of 100kbits/second.
	// * @NL80211_RATE_INFO_BITRATE: total bitrate (u16, 100kbit/s)
	rateinfo.Bitrate *= 100 * 1000

	return rateinfo, nil
}

// parseSurveyInfo parses a single SurveyInfo from a byte slice of netlink
// attributes.
func parseSurveyInfo(b []byte) (*SurveyInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info SurveyInfo
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_IFINDEX:
			info.InterfaceIndex = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_ATTR_SURVEY_INFO:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if err := (&info).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			// Parsed the necessary data.
			return &info, nil
		}
	}

	// No survey info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a SurveyInfo's fields.
func (s *SurveyInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_SURVEY_INFO_FREQUENCY:
			s.Frequency = int(binary.NativeEndian.Uint32(a.Data))
		case unix.NL80211_SURVEY_INFO_NOISE:
			s.Noise = int(int8(a.Data[0]))
		case unix.NL80211_SURVEY_INFO_IN_USE:
			s.InUse = true
		case unix.NL80211_SURVEY_INFO_TIME:
			s.ChannelTime = time.Duration(binary.NativeEndian.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_BUSY:
			s.ChannelTimeBusy = time.Duration(binary.NativeEndian.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_EXT_BUSY:
			s.ChannelTimeExtBusy = time.Duration(binary.NativeEndian.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_BSS_RX:
			s.ChannelTimeBssRx = time.Duration(binary.NativeEndian.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_RX:
			s.ChannelTimeRx = time.Duration(binary.NativeEndian.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_TX:
			s.ChannelTimeTx = time.Duration(binary.NativeEndian.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_SCAN:
			s.ChannelTimeScan = time.Duration(binary.NativeEndian.Uint64(a.Data)) * time.Millisecond
		}
	}

	return nil
}

// attrsContain checks if a slice of netlink attributes contains an attribute
// with the specified type.
func attrsContain(attrs []netlink.Attribute, typ uint16) bool {
	for _, a := range attrs {
		if a.Type == typ {
			return true
		}
	}

	return false
}

// decodeSSID safely parses a byte slice into UTF-8 runes, and returns the
// resulting string from the runes.
func decodeSSID(b []byte) string {
	buf := bytes.NewBuffer(nil)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]

		buf.WriteRune(r)
	}

	return buf.String()
}

// decodeBSSLoad Decodes the BSSLoad IE. Supports Version 1 and Version 2
// values according to https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c
// See also source code of iw (v5.19) scan.c Line 1634ff
// BSS Load ELement (with length 5) is defined by chapter 9.4.2.27 (page 1066) of the current IEEE 802.11-2020
func decodeBSSLoad(b []byte) (*BSSLoad, error) {
	var load BSSLoad
	if len(b) == 5 {
		// Wireshark calls this "802.11e CCA Version"
		// This is the version defined in IEEE 802.11 (Versions 2007, 2012, 2016 and 2020)
		load.Version = 2
		load.StationCount = binary.LittleEndian.Uint16(b[0:2])               // first 2 bytes
		load.ChannelUtilization = b[2]                                       // next 1 byte
		load.AvailableAdmissionCapacity = binary.LittleEndian.Uint16(b[3:5]) // last 2 bytes
	} else if len(b) == 4 {
		// Wireshark calls this "Cisco QBSS Version 1 - non CCA"
		load.Version = 1
		load.StationCount = binary.LittleEndian.Uint16(b[0:2]) // first 2 bytes
		load.ChannelUtilization = b[2]                         // next 1 byte
		load.AvailableAdmissionCapacity = uint16(b[3])         // next 1 byte
	} else {
		return nil, errInvalidBSSLoad
	}
	return &load, nil
}

// decodeRSN parses IEEE 802.11 Element ID 48 (RSN Information Element).
// (RSN = Robust Security Network)
//
// The RSN IE structure is defined in IEEE 802.11-2020 standard, section 9.4.2.24 (page 1051).
func decodeRSN(b []byte) (*RSNInfo, error) {
	// IEEE 802.11 Information Elements are limited to 255 octets total (ID + Length + Data)
	// Since we receive only the data portion, maximum size is 253 bytes (255 - 1 - 1)
	if len(b) > 253 {
		return &RSNInfo{}, errRSNDataTooLarge
	}

	if len(b) < 8 { // minimum: version(2) + group cipher(4) + pairwise count(2)
		return &RSNInfo{}, errRSNTooShort
	}

	var ri RSNInfo
	ri.Version = binary.LittleEndian.Uint16(b[:2])

	// Note: Most implementations use version 1, but be tolerant of future versions
	// that maintain backward compatibility. Only reject version 0 as invalid.
	if ri.Version == 0 {
		return &ri, errRSNInvalidVersion
	}

	// Group cipher suite (4 octets) - OUI is stored big-endian in the data
	groupCipherOUI := binary.BigEndian.Uint32(b[2:6])
	ri.GroupCipher = RSNCipher(groupCipherOUI)
	pos := 6

	// Pairwise cipher list
	if len(b) < pos+2 {
		return &ri, errRSNTruncatedPairwiseCount
	}
	pcCount := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
	pos += 2

	if pcCount > 60 { // (253-10)/4 ≈ 60 (theoretical max with minimal overhead)
		return &ri, errRSNPairwiseCipherCountTooLarge
	}

	if len(b) < pos+4*pcCount {
		return &ri, errRSNTruncatedPairwiseList
	}

	ri.PairwiseCiphers = make([]RSNCipher, 0, pcCount) // Pre-allocate with known capacity
	for range pcCount {
		sel := binary.BigEndian.Uint32(b[pos : pos+4])
		ri.PairwiseCiphers = append(ri.PairwiseCiphers, RSNCipher(sel))
		pos += 4
	}

	// AKM list
	if len(b) < pos+2 {
		return &ri, nil // AKM list is optional, return what we have
	}
	akmCount := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
	pos += 2

	if akmCount > 60 { // (253-10)/4 ≈ 60 (theoretical max with minimal overhead)
		return &ri, errRSNAKMCountTooLarge
	}

	if len(b) < pos+4*akmCount {
		return &ri, errRSNTruncatedAKMList
	}
	// Additional validation: check if we have enough space for the current counts
	// Calculate minimum required space for what we've parsed so far
	minRequired := 6 + 2 + 4*pcCount + 2 + 4*akmCount // version + group + pairwise_count + pairwise + akm_count + akms
	if len(b) < minRequired {
		return &ri, errRSNTooSmallForCounts
	}

	ri.AKMs = make([]RSNAKM, 0, akmCount) // Pre-allocate with known capacity
	for range akmCount {
		sel := binary.BigEndian.Uint32(b[pos : pos+4])
		ri.AKMs = append(ri.AKMs, RSNAKM(sel))
		pos += 4
	}

	// Capabilities (optional)
	if len(b) >= pos+2 {
		ri.Capabilities = binary.LittleEndian.Uint16(b[pos : pos+2])
		pos += 2
	}

	// PMKID list – skip if present, with proper bounds checking
	if len(b) >= pos+2 {
		pmkCount := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
		pos += 2

		if pmkCount > 15 { // (253-10)/16 ≈ 15 (theoretical max with minimal overhead)
			return &ri, errRSNPMKIDCountTooLarge
		}

		// Check if we have enough bytes for all PMKIDs
		if len(b) < pos+16*pmkCount {
			return &ri, errRSNTruncatedPMKIDList
		}
		pos += 16 * pmkCount
	}

	// Group‑management cipher (optional, WPA3/802.11w)
	if len(b) >= pos+4 {
		gmCipherOUI := binary.BigEndian.Uint32(b[pos : pos+4])
		ri.GroupMgmtCipher = RSNCipher(gmCipherOUI)
	}

	return &ri, nil
}

// checkExtFeature Checks if a physical interface supports a extended feature
func (c *client) checkExtFeature(ifi *Interface, feature uint) (bool, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_WIPHY,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Flag(unix.NL80211_ATTR_SPLIT_WIPHY_DUMP, true)
		},
	)
	if err != nil {
		return false, err
	}

	var features []byte
found:
	for i := range msgs {
		attrs, err := netlink.UnmarshalAttributes(msgs[i].Data)
		if err != nil {
			return false, err
		}
		for _, a := range attrs {
			if a.Type == unix.NL80211_ATTR_EXT_FEATURES {
				features = a.Data
				break found
			}
		}
	}

	if feature/8 >= uint(len(features)) {
		return false, nil
	}

	return (features[feature/8]&(1<<(feature%8)) != 0), nil
}

// parseAttributes parses netlink attributes into a RegulatoryDomain's fields.
func (d *RegulatoryDomain) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_REG_ALPHA2:
			d.Region = nlenc.String(a.Data)
		}
	}

	return nil
}
