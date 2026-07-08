package dnslookup

import (
	"testing"
	"time"
)

func TestNewResolver(t *testing.T) {
	r := NewResolver()
	if r == nil {
		t.Fatal("NewResolver returned nil")
	}
	if r.timeout == 0 {
		t.Error("Expected non-zero timeout")
	}
}

func TestNewResolverWithTimeout(t *testing.T) {
	r := NewResolverWithTimeout(5)
	if r == nil {
		t.Fatal("NewResolverWithTimeout returned nil")
	}
	if r.timeout != 5 {
		t.Errorf("timeout = %d, want 5", r.timeout)
	}
}

func TestTXTCache(t *testing.T) {
	cache := newTXTCache(1 * time.Second)
	// Set a value
	cache.set("example.com", []string{"v=spf1 ip4:1.2.3.4"})
	// Get it back
	records, ok := cache.get("example.com")
	if !ok {
		t.Fatal("cache.get returned not ok")
	}
	if len(records) != 1 || records[0] != "v=spf1 ip4:1.2.3.4" {
		t.Errorf("cache value = %v, want v=spf1 ip4:1.2.3.4", records)
	}
}

func TestTXTCacheMiss(t *testing.T) {
	cache := newTXTCache(1 * time.Second)
	_, ok := cache.get("example.com")
	if ok {
		t.Error("cache should return not ok for miss")
	}
}
