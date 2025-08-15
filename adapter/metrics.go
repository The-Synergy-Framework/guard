package adapter

import (
	"context"

	"core/metrics"
)

// adapterMetrics holds metrics for monitoring provider operations.
type adapterMetrics struct {
	requestTotal   metrics.Counter
	requestLatency metrics.Histogram
	cacheHits      metrics.Counter
	cacheMisses    metrics.Counter
	retryTotal     metrics.Counter
	errorTotal     metrics.Counter
}

// newAdapterMetrics creates metrics instruments for the adapter.
func newAdapterMetrics(registry metrics.Registry, labels metrics.Labels) (*adapterMetrics, error) {
	m := &adapterMetrics{}

	var err error
	m.requestTotal, err = registry.NewCounter(metrics.MetricOptions{
		Name:        "auth_provider_requests_total",
		Help:        "Total number of requests to the auth provider",
		Unit:        "requests",
		ConstLabels: labels,
	})
	if err != nil {
		return nil, err
	}

	m.requestLatency, err = registry.NewHistogram(metrics.HistogramOptions{
		MetricOptions: metrics.MetricOptions{
			Name:        "auth_provider_request_duration_seconds",
			Help:        "Duration of auth provider requests",
			Unit:        "seconds",
			ConstLabels: labels,
		},
	})
	if err != nil {
		return nil, err
	}

	m.cacheHits, err = registry.NewCounter(metrics.MetricOptions{
		Name:        "auth_provider_cache_hits_total",
		Help:        "Total number of cache hits",
		Unit:        "hits",
		ConstLabels: labels,
	})
	if err != nil {
		return nil, err
	}

	m.cacheMisses, err = registry.NewCounter(metrics.MetricOptions{
		Name:        "auth_provider_cache_misses_total",
		Help:        "Total number of cache misses",
		Unit:        "misses",
		ConstLabels: labels,
	})
	if err != nil {
		return nil, err
	}

	m.retryTotal, err = registry.NewCounter(metrics.MetricOptions{
		Name:        "auth_provider_retries_total",
		Help:        "Total number of retried operations",
		Unit:        "retries",
		ConstLabels: labels,
	})
	if err != nil {
		return nil, err
	}

	m.errorTotal, err = registry.NewCounter(metrics.MetricOptions{
		Name:        "auth_provider_errors_total",
		Help:        "Total number of provider errors",
		Unit:        "errors",
		ConstLabels: labels,
	})
	if err != nil {
		return nil, err
	}

	return m, nil
}

// recordRequest records a request metric with duration.
func (m *adapterMetrics) recordRequest(ctx context.Context, operation string, duration float64) {
	labels := metrics.Labels{"operation": operation}
	m.requestTotal.Inc(ctx, labels)
	m.requestLatency.Observe(ctx, duration, labels)
}

// recordCacheHit records a cache hit.
func (m *adapterMetrics) recordCacheHit(ctx context.Context, cacheType string) {
	m.cacheHits.Inc(ctx, metrics.Labels{"type": cacheType})
}

// recordCacheMiss records a cache miss.
func (m *adapterMetrics) recordCacheMiss(ctx context.Context, cacheType string) {
	m.cacheMisses.Inc(ctx, metrics.Labels{"type": cacheType})
}

// recordRetry records a retry attempt.
func (m *adapterMetrics) recordRetry(ctx context.Context, operation string, attempt int) {
	m.retryTotal.Inc(ctx, metrics.Labels{
		"operation": operation,
	})
}

// recordError records a provider error.
func (m *adapterMetrics) recordError(ctx context.Context, operation string, errorClass string) {
	m.errorTotal.Inc(ctx, metrics.Labels{
		"operation":   operation,
		"error_class": errorClass,
	})
}
