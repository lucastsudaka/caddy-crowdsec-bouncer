package layer4

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	l4 "github.com/mholt/caddy-l4/layer4"
	model "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
)

const layer4TestClientIP = "192.0.2.30"

func TestDecisionRemediationMetrics(t *testing.T) {
	tests := []struct {
		name                string
		decisionType        string
		expectedRemediation string
	}{
		{
			name:                "captcha falls back to connection ban",
			decisionType:        " CAPTCHA ",
			expectedRemediation: "ban",
		},
		{
			name:                "non-captcha remediation is preserved",
			decisionType:        "throttle",
			expectedRemediation: "throttle",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "test-key", r.Header.Get("X-Api-Key"))
				assert.Equal(t, layer4TestClientIP, r.URL.Query().Get("ip"))
				_, _ = fmt.Fprintf(
					w,
					`[{"duration":"1h","id":1,"origin":"cscli","scenario":"test","scope":"Ip","type":%q,"value":%q}]`,
					test.decisionType,
					layer4TestClientIP,
				)
			}))
			t.Cleanup(lapi.Close)

			streaming := false
			enableCaddyMetrics := true
			cs := &crowdsec.CrowdSec{
				APIUrl:             lapi.URL,
				APIKey:             "test-key",
				EnableStreaming:    &streaming,
				MetricsInterval:    caddy.Duration(time.Hour),
				EnableCaddyMetrics: &enableCaddyMetrics,
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
			t.Cleanup(cancel)
			require.NoError(t, cs.Provision(ctx))

			logger := zaptest.NewLogger(t)
			matcher := Matcher{crowdsec: cs, logger: logger}
			connection := l4.WrapConnection(
				&fixedConnection{
					local:  fixedAddress("127.0.0.1:443"),
					remote: fixedAddress(layer4TestClientIP + ":12345"),
				},
				nil,
				logger,
			)

			matched, err := matcher.Match(connection)
			require.NoError(t, err)
			assert.False(t, matched)

			metricFamilies, err := ctx.GetMetricsRegistry().Gather()
			require.NoError(t, err)
			assert.Equal(t, 1.0, counterValue(t, metricFamilies, "crowdsec_requests_blocked", map[string]string{
				"ip_type":     "ipv4",
				"origin":      "cscli",
				"remediation": test.expectedRemediation,
				"server":      "layer4-127.0.0.1:443",
			}))
		})
	}
}

func counterValue(
	t *testing.T,
	metricFamilies []*model.MetricFamily,
	name string,
	wantedLabels map[string]string,
) float64 {
	t.Helper()
	for _, family := range metricFamilies {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := make(map[string]string, len(metric.GetLabel()))
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			if assert.ObjectsAreEqual(wantedLabels, labels) {
				return metric.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("counter %q with labels %v not found", name, wantedLabels)
	return 0
}

type fixedAddress string

func (fixedAddress) Network() string        { return "tcp" }
func (address fixedAddress) String() string { return string(address) }

type fixedConnection struct {
	local  net.Addr
	remote net.Addr
}

func (*fixedConnection) Read([]byte) (int, error)         { return 0, io.EOF }
func (*fixedConnection) Write(body []byte) (int, error)   { return len(body), nil }
func (*fixedConnection) Close() error                     { return nil }
func (connection *fixedConnection) LocalAddr() net.Addr   { return connection.local }
func (connection *fixedConnection) RemoteAddr() net.Addr  { return connection.remote }
func (*fixedConnection) SetDeadline(time.Time) error      { return nil }
func (*fixedConnection) SetReadDeadline(time.Time) error  { return nil }
func (*fixedConnection) SetWriteDeadline(time.Time) error { return nil }
