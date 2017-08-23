// Library took from https://github.com/jpillora/ipfilter
// Mechanism for blocking countries has been removed mostly to not load geolite db for countries from http://geolite.maxmind.com
// (and also to not have any mutex)
//
//#### MIT License
//
//Copyright © 2016 <dev@jpillora.com>
//
//Permission is hereby granted, free of charge, to any person obtaining
//a copy of this software and associated documentation files (the
//'Software'), to deal in the Software without restriction, including
//without limitation the rights to use, copy, modify, merge, publish,
//distribute, sublicense, and/or sell copies of the Software, and to
//permit persons to whom the Software is furnished to do so, subject to
//the following conditions:
//
//The above copyright notice and this permission notice shall be
//included in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
//EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
//SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
package ipfiltering

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	XFFHeader = "X-Forwarded-For"
)

//Options for IPFilter. Allowed takes precendence over Blocked.
//IPs can be IPv4 or IPv6 and can optionally contain subnet
//masks (/24). Note however, determining if a given IP is
//included in a subnet requires a linear scan so is less performant
//than looking up single IPs.
//
//This could be improved with some algorithmic magic.
type Options struct {
	//explicity allowed IPs
	AllowedIPs []string
	//explicity blocked IPs
	BlockedIPs []string
	//block by default (defaults to allow)
	BlockByDefault bool

	Logger interface {
		Printf(format string, v ...interface{})
	}
}

type IpFiltering struct {
	opts           Options
	defaultAllowed bool
	ips            map[string]bool
	codes          map[string]bool
	subnets        []*subnet
}

type subnet struct {
	str     string
	ipnet   *net.IPNet
	allowed bool
}

//who uses the new builtin anyway?
func New(opts Options) *IpFiltering {

	if opts.Logger == nil {
		flags := log.LstdFlags
		opts.Logger = log.New(os.Stdout, "", flags)
	}
	f := &IpFiltering{
		opts:           opts,
		ips:            map[string]bool{},
		codes:          map[string]bool{},
		defaultAllowed: !opts.BlockByDefault,
	}
	for _, ip := range opts.BlockedIPs {
		f.BlockIP(ip)
	}
	for _, ip := range opts.AllowedIPs {
		f.AllowIP(ip)
	}
	return f
}

func (f *IpFiltering) AllowIP(ip string) bool {
	return f.ToggleIP(ip, true)
}

func (f *IpFiltering) BlockIP(ip string) bool {
	return f.ToggleIP(ip, false)
}

func (f *IpFiltering) ToggleIP(str string, allowed bool) bool {
	//check if has subnet
	if ip, netAddress, err := net.ParseCIDR(str); err == nil {
		// containing only one ip?
		if n, total := netAddress.Mask.Size(); n == total {
			f.ips[ip.String()] = allowed
			return true
		}
		//check for existing
		found := false
		for _, subnet := range f.subnets {
			if subnet.str == str {
				found = true
				subnet.allowed = allowed
				break
			}
		}
		if !found {
			f.subnets = append(f.subnets, &subnet{
				str:     str,
				ipnet:   netAddress,
				allowed: allowed,
			})
		}
		return true
	}
	//check if plain ip
	if ip := net.ParseIP(str); ip != nil {
		f.ips[ip.String()] = allowed
		return true
	}
	return false
}

//ToggleDefault alters the default setting
func (f *IpFiltering) ToggleDefault(allowed bool) {
	f.defaultAllowed = allowed
}

//Allowed returns if a given IP can pass through the filter
func (f *IpFiltering) Allowed(ipstr string) bool {
	return f.NetAllowed(net.ParseIP(ipstr))
}

//Allowed returns if a given net.IP can pass through the filter
func (f *IpFiltering) NetAllowed(ip net.IP) bool {
	//invalid ip
	if ip == nil {
		return false
	}
	//read lock entire function
	//except for db access
	//check single ips
	allowed, ok := f.ips[ip.String()]
	if ok {
		return allowed
	}
	//scan subnets for any allow/block
	blocked := false
	for _, subnet := range f.subnets {
		if subnet.ipnet.Contains(ip) {
			if subnet.allowed {
				return true
			}
			blocked = true
		}
	}
	if blocked {
		return false
	}
	return f.defaultAllowed
}

//Blocked returns if a given IP can NOT pass through the filter
func (f *IpFiltering) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

//Blocked returns if a given net.IP can NOT pass through the filter
func (f *IpFiltering) NetBlocked(ip net.IP) bool {
	return !f.NetAllowed(ip)
}

//Wrap the provided handler with simple IP blocking middleware
//using this IP filter and its configuration
func Middleware(next http.Handler, options MiddlewareOptions) http.Handler {
	return &ipFilteringMiddleware{IpFiltering: New(options.Options), options: options, next: next}
}
type MiddlewareOptions struct {
	Options
	TrustXFFHeader bool
}
type ipFilteringMiddleware struct {
	*IpFiltering
	next http.Handler
	options MiddlewareOptions
}
func (m ipFilteringMiddleware) getIp(r *http.Request) string {
	remoteAddr := r.RemoteAddr
	if m.options.TrustXFFHeader && r.Header.Get(XFFHeader) != "" {
		remoteAddr = strings.TrimSpace(strings.Split(r.Header.Get(XFFHeader), ",")[0])
	}
	ip, _, _ := net.SplitHostPort(remoteAddr)
	return ip
}
func (m *ipFilteringMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//show simple forbidden text
	if !m.IpFiltering.Allowed(m.getIp(r)) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}
