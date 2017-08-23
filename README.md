# ipfiltering

A package for IP Filtering in Go(lang) made by [jpillora](https://github.com/jpillora/ipfilter) without geo location and with a middleware which support `X-Forwarded-For` header.

On thi repo, Mechanism for blocking countries has been removed mostly to not load geolite db 
for countries from http://geolite.maxmind.com (and also to not have any mutex).

Refactor was too aggressive to be merged, mostly because we don't want mutex and countries.

### Install

```
go get github.com/orange-cloudfoundry/ipfiltering
```

### Features

* Simple
* IPv4 / IPv6 support
* Subnet support
* Simple HTTP middleware

### Usage


**HTTP Middleware**

```go
h := http.Handler(...)
myProtectedHandler := ipfiltering.Middleware(h, ipfiltering.MiddlewareOptions{
    AllowedIPs: []string{"192.168.0.0/24"},
    // if set to true if request contains a X-Forwarded-For it will use client ip from this header
    // This heander can be easily overwritten by a malicious reverse proxy, be sure of what you have before
    TrustXFFHeader: true, 
})
http.ListenAndServe(":8080", myProtectedHandler)
```

**Allow your LAN only**

```go
f := ipfiltering.New(ipfilter.Options{
    AllowedIPs: []string{"192.168.0.0/24"},
    BlockByDefault: true,
})
//only allow 192.168.0.X IPs
f.Allowed("192.168.0.42") //=> true
f.Allowed("10.0.0.42") //=> false
```

... and with dynamic list updates

```go
//and allow 10.X.X.X
f.AllowIP("10.0.0.0/8")
f.Allowed("10.0.0.42") //=> true
f.Allowed("203.25.111.68") //=> false
f.Allowed("203.25.111.68") //=> true
```

**Check with `net.IP`**

```go
f.NetAllowed(net.IP{203,25,111,68}) //=> true
```

**Advanced HTTP middleware**

Make your own with:

```go
func (m *myMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//use remote addr as it cant be spoofed
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	//show simple forbidden text
	if !m.IPFilter.Allowed(ip) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}
```



