package ipfiltering

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSingleIP(t *testing.T) {
	f := New(Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be allowed")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestSubnetIP(t *testing.T) {
	f := New(Options{
		AllowedIPs:     []string{"10.0.0.0/16"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("10.0.0.1"), "[1] should be allowed")
	assert.True(t, f.Allowed("10.0.42.1"), "[2] should be allowed")
	assert.True(t, f.Blocked("10.42.0.1"), "[3] should be blocked")
}

func TestDynamicList(t *testing.T) {
	f := New(Options{})
	assert.True(t, f.Allowed("116.31.116.51"), "[1] IP should be allowed")
	f.BlockIP("116.31.116.51")
	assert.True(t, f.Blocked("116.31.116.51"), "[1] IP should be blocked")
}
