package config

import (
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

var (
	containerOnce sync.Once
	inContainer   bool
)

// InContainerRuntime reports whether this process is running inside a Docker or
// OCI container. The check is cached because address translation is used on
// several hot configuration paths.
func InContainerRuntime() bool {
	containerOnce.Do(func() {
		if _, err := os.Stat("/.dockerenv"); err == nil {
			inContainer = true
			return
		}
		if _, err := os.Stat("/run/.containerenv"); err == nil {
			inContainer = true
			return
		}
		switch strings.ToLower(strings.TrimSpace(os.Getenv("container"))) {
		case "docker", "podman", "containerd", "oci":
			inContainer = true
		}
	})
	return inContainer
}

// RuntimeLoopbackHost is the hostname a process should use to reach a service
// running on the physical host.
func RuntimeLoopbackHost() string {
	if InContainerRuntime() {
		return "host.docker.internal"
	}
	return "127.0.0.1"
}

// TranslateRuntimeHost rewrites only well-known host/container aliases. Public
// targets and remote proxies are returned unchanged.
func TranslateRuntimeHost(host string) string {
	return translateRuntimeHostFor(host, InContainerRuntime())
}

func translateRuntimeHostFor(host string, inDocker bool) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	switch {
	case inDocker && isLoopbackHost(host):
		return "host.docker.internal"
	case !inDocker && (strings.EqualFold(host, "host.docker.internal") ||
		strings.EqualFold(host, "gateway.docker.internal")):
		return "127.0.0.1"
	default:
		return host
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// TranslateRuntimeURL rewrites a URL's host when moving the same configuration
// between an application container and a host binary.
func TranslateRuntimeURL(raw string) string {
	return translateRuntimeURLFor(raw, InContainerRuntime())
}

func translateRuntimeURLFor(raw string, inDocker bool) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return raw
	}
	host := translateRuntimeHostFor(u.Hostname(), inDocker)
	if host == u.Hostname() {
		return raw
	}
	port := u.Port()
	if port == "" {
		u.Host = host
	} else {
		u.Host = net.JoinHostPort(host, port)
	}
	return u.String()
}
