package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	middlewares "github.com/Laisky/gin-middlewares"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"
)

// TestMetricsMethodCardinalityBounded rejects unbounded labels from a finite sample of unknown HTTP methods.
func TestMetricsMethodCardinalityBounded(t *testing.T) {
	registry := prometheus.NewRegistry()
	requests := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "fixture_requests_total", Help: "Local fixture request count."},
		[]string{"method"})
	require.NoError(t, registry.Register(requests))
	handler := promhttp.InstrumentHandlerCounter(requests, http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}))
	const unknownMethods = 24
	for index := 0; index < unknownMethods; index++ {
		request := httptest.NewRequest(fmt.Sprintf("UNREGISTERED%d", index), "http://fixture.example.test/", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, http.StatusNoContent, response.Code)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://fixture.example.test/", nil))
	require.Equal(t, http.StatusNoContent, response.Code)
	families, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)
	// Unknown method names share one bounded series; ordinary GET retains its usual label.
	require.Len(t, families[0].Metric, 2)
	values := make(map[string]float64)
	for _, metric := range families[0].Metric {
		require.Len(t, metric.Label, 1)
		require.Equal(t, "method", metric.Label[0].GetName())
		values[metric.Label[0].GetValue()] = metric.Counter.GetValue()
	}
	require.Equal(t, map[string]float64{"unknown": unknownMethods, "get": 1}, values)
}

// TestMetricsRouteFiltersUnknownMethods exercises the application's actual metrics middleware and GET routing.
func TestMetricsRouteFiltersUnknownMethods(t *testing.T) {
	registry := prometheus.NewRegistry()
	previousRegisterer, previousGatherer := prometheus.DefaultRegisterer, prometheus.DefaultGatherer
	prometheus.DefaultRegisterer, prometheus.DefaultGatherer = registry, registry
	t.Cleanup(func() {
		prometheus.DefaultRegisterer, prometheus.DefaultGatherer = previousRegisterer, previousGatherer
	})
	router := gin.New()
	middlewares.BindPrometheus(router)
	for index := 0; index < 24; index++ {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(
			fmt.Sprintf("UNREGISTERED%d", index), "http://fixture.example.test/metrics", nil))
		require.Equal(t, http.StatusNotFound, response.Code)
	}
	require.Equal(t, float64(0), metricsHandlerRequests(t, registry),
		"unknown methods must not reach promhttp's metrics handler")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://fixture.example.test/metrics", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), "promhttp_metric_handler_requests_total")
	require.Equal(t, float64(1), metricsHandlerRequests(t, registry))
}

// metricsHandlerRequests reads the generated registry's metrics-handler request counter.
func metricsHandlerRequests(t *testing.T, registry *prometheus.Registry) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	var count float64
	for _, family := range families {
		if family.GetName() != "promhttp_metric_handler_requests_total" {
			continue
		}
		for _, metric := range family.Metric {
			count += metric.Counter.GetValue()
		}
	}
	return count
}
