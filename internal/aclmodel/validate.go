package aclmodel

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// InputRule is one rule as submitted by the editor: the rule plus its
// UI-local metadata.
type InputRule struct {
	Action      string   `json:"action"`
	Proto       string   `json:"proto,omitempty"`
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
}

// Rule returns the policy rule part of an InputRule.
func (r InputRule) Rule() Rule {
	return Normalize(Rule{Action: r.Action, Proto: r.Proto, Src: r.Src, Dst: r.Dst})
}

// Input is the editor's submitted model. A nil map/slice means "leave this
// section untouched"; an empty one means "make it empty".
type Input struct {
	Groups    map[string][]string `json:"groups"`
	TagOwners map[string][]string `json:"tagOwners"`
	Hosts     map[string]string   `json:"hosts"`
	Rules     []InputRule         `json:"rules"`
}

// EnabledRules returns the rules that belong in the live policy, in order.
func (in *Input) EnabledRules() []Rule {
	out := make([]Rule, 0, len(in.Rules))
	for _, r := range in.Rules {
		if r.Enabled {
			out = append(out, r.Rule())
		}
	}
	return out
}

// ValidationError names the offending field.
type ValidationError struct {
	Path string
	Msg  string
}

func (e *ValidationError) Error() string { return e.Path + ": " + e.Msg }

func verr(path, format string, args ...any) error {
	return &ValidationError{Path: path, Msg: fmt.Sprintf(format, args...)}
}

const (
	MaxNameLen        = 120
	MaxDescriptionLen = 2000
)

var (
	groupKeyRe = regexp.MustCompile(`^group:\S+$`)
	tagKeyRe   = regexp.MustCompile(`^tag:[A-Za-z]\S*$`)
	portsRe    = regexp.MustCompile(`^(\*|\d+(-\d+)?)(,\d+(-\d+)?)*$`)
	digitsRe   = regexp.MustCompile(`^\d+$`)
)

// Protocol names headscale accepts (numbers are accepted too).
var knownProtos = map[string]bool{
	"tcp": true, "udp": true, "icmp": true, "ipv6-icmp": true, "igmp": true, "ipv4": true,
	"ip-in-ip": true, "egp": true, "igp": true, "gre": true, "esp": true, "ah": true,
	"sctp": true, "fc": true, "*": true,
}

// SplitDst splits a destination into its target and port spec at the last
// colon (the port spec never contains one, so IPv6 targets are safe).
func SplitDst(dst string) (target, ports string, ok bool) {
	i := strings.LastIndex(dst, ":")
	if i <= 0 || i == len(dst)-1 {
		return "", "", false
	}
	return dst[:i], dst[i+1:], true
}

// Validate performs shape validation of editor input. Semantics (do the
// groups exist, are the CIDRs allowed, ...) are left to headscale's own
// policy check, which runs before every save.
func Validate(in *Input) error {
	for k, members := range in.Groups {
		p := "groups[" + k + "]"
		if !groupKeyRe.MatchString(k) {
			return verr(p, `group names look like "group:name" (no whitespace)`)
		}
		if members == nil {
			return verr(p, "members must be an array")
		}
		for i, m := range members {
			if err := checkUser(fmt.Sprintf("%s[%d]", p, i), m); err != nil {
				return err
			}
		}
	}
	for k, owners := range in.TagOwners {
		p := "tagOwners[" + k + "]"
		if !tagKeyRe.MatchString(k) {
			return verr(p, `tag names look like "tag:name" (letter first, no whitespace)`)
		}
		if owners == nil {
			return verr(p, "owners must be an array")
		}
		for i, o := range owners {
			op := fmt.Sprintf("%s[%d]", p, i)
			if strings.HasPrefix(o, "group:") {
				if !groupKeyRe.MatchString(o) {
					return verr(op, "invalid group reference %q", o)
				}
				continue
			}
			if err := checkUser(op, o); err != nil {
				return err
			}
		}
	}
	for k, v := range in.Hosts {
		p := "hosts[" + k + "]"
		if k == "" || strings.ContainsAny(k, " \t\r\n:") {
			return verr(p, "host names cannot be empty or contain whitespace or colons")
		}
		if _, err := netip.ParseAddr(v); err != nil {
			if _, err := netip.ParsePrefix(v); err != nil {
				return verr(p, "%q is not an IP address or CIDR", v)
			}
		}
	}
	for i, r := range in.Rules {
		p := fmt.Sprintf("rules[%d]", i)
		n := r.Rule()
		if n.Action != "accept" {
			return verr(p+".action", `must be "accept"`)
		}
		if n.Proto != "" && !knownProtos[n.Proto] && !digitsRe.MatchString(n.Proto) {
			return verr(p+".proto", "unknown protocol %q", r.Proto)
		}
		if len(n.Src) == 0 {
			return verr(p+".src", "at least one source is required")
		}
		for j, s := range n.Src {
			if s == "" || strings.ContainsAny(s, " \t\r\n") {
				return verr(fmt.Sprintf("%s.src[%d]", p, j), "sources cannot be empty or contain whitespace")
			}
		}
		if len(n.Dst) == 0 {
			return verr(p+".dst", "at least one destination is required")
		}
		for j, d := range n.Dst {
			dp := fmt.Sprintf("%s.dst[%d]", p, j)
			if strings.ContainsAny(d, " \t\r\n") {
				return verr(dp, "destinations cannot contain whitespace")
			}
			target, ports, ok := SplitDst(d)
			if !ok || !portsRe.MatchString(ports) {
				return verr(dp, `destination must be "<target>:<ports>", e.g. "tag:web:443", "10.0.0.0/24:22-25" or "*:*"`)
			}
			_ = target
		}
		if len(r.Name) > MaxNameLen {
			return verr(p+".name", "at most %d characters", MaxNameLen)
		}
		if len(r.Description) > MaxDescriptionLen {
			return verr(p+".description", "at most %d characters", MaxDescriptionLen)
		}
	}
	return nil
}

func checkUser(path, u string) error {
	if u == "" || strings.ContainsAny(u, " \t\r\n") {
		return verr(path, "users cannot be empty or contain whitespace")
	}
	if !strings.Contains(u, "@") {
		return verr(path, `users must be written as "name@" or as an email address`)
	}
	return nil
}
