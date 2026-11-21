package elb

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

const defaultHMMaxRetriesDown = 3

var (
	hmDomainRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)
	hmURLPathRE = regexp.MustCompile(`^/[A-Za-z0-9\-/.%?#&_;~!()*[\]@$^:',+=]*$`)
)

type createHealthMonitorInput struct {
	PoolID         string
	Name           string
	Type           string
	Delay          int
	Timeout        int
	MaxRetries     int
	MaxRetriesDown *int
	MonitorPort    *int
	HTTPMethod     *string
	URLPath        *string
	ExpectedCodes  *string
	DomainName     *string
	AdminStateUp   *bool
}

type updateHealthMonitorInput struct {
	Name           *string
	Type           *string
	Delay          *int
	Timeout        *int
	MaxRetries     *int
	MaxRetriesDown *int
	MonitorPort    poolOptional[int]
	HTTPMethod     *string
	URLPath        *string
	ExpectedCodes  *string
	DomainName     poolOptional[string]
	AdminStateUp   *bool
}

type listHealthMonitorsFilter struct {
	IDs                  []string
	Names                []string
	Types                []string
	MonitorPorts         []int
	DomainNames          []string
	Delays               []int
	Timeouts             []int
	MaxRetries           []int
	MaxRetriesDown       []int
	AdminStateUp         *bool
	ExpectedCodes        []string
	URLPaths             []string
	HTTPMethods          []string
	EnterpriseProjectIDs []string
	Page                 pagination.Marker
	PageReverse          bool
}

func hmValidType(typ string) bool {
	switch typ {
	case "TCP", "UDP_CONNECT", "HTTP", "HTTPS", "GRPC", "TLS":
		return true
	default:
		return false
	}
}

func hmPoolProtocolAllowed(poolProto, hmType string) bool {
	switch poolProto {
	case "UDP", "QUIC":
		return hmType == "UDP_CONNECT"
	case "TCP":
		return hmType == "TCP" || hmType == "HTTP" || hmType == "HTTPS"
	case "HTTP", "HTTPS", "GRPC", "TLS":
		return hmType == "TCP" || hmType == "HTTP" || hmType == "HTTPS" || hmType == "GRPC" || hmType == "TLS"
	default:
		return false
	}
}

func hmIsHTTPFamily(typ string) bool {
	return typ == "HTTP" || typ == "HTTPS" || typ == "GRPC"
}

func hmValidHTTPMethod(m string) bool {
	return m == "GET" || m == "HEAD" || m == "POST"
}

func hmValidURLPath(p string) bool {
	if p == "" || utf8.RuneCountInString(p) > 255 {
		return false
	}
	return hmURLPathRE.MatchString(p)
}

func hmValidExpectedCodes(s string) bool {
	if s == "" {
		return false
	}
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if loStr, hiStr, isRange := strings.Cut(part, "-"); isRange {
			lo, err1 := strconv.Atoi(loStr)
			hi, err2 := strconv.Atoi(hiStr)
			if err1 != nil || err2 != nil || lo < 0 || hi > 599 || lo > hi {
				return false
			}
		} else {
			v, err := strconv.Atoi(part)
			if err != nil || v < 0 || v > 599 {
				return false
			}
		}
	}
	return true
}

func hmValidDomainName(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > 100 {
		return false
	}
	return hmDomainRE.MatchString(s)
}

func (s *Service) createHealthMonitor(ctx context.Context, t Tenant, in createHealthMonitorInput) (healthMonitor, error) {
	if in.PoolID == "" {
		return healthMonitor{}, errInvalidInput("pool_id")
	}
	if !validName(in.Name) {
		return healthMonitor{}, errInvalidInput("name")
	}
	if !hmValidType(in.Type) {
		return healthMonitor{}, errInvalidInput("type")
	}
	if in.Delay < 1 || in.Delay > 50 {
		return healthMonitor{}, errInvalidInput("delay")
	}
	if in.Timeout < 1 {
		return healthMonitor{}, errInvalidInput("timeout")
	}
	if in.MaxRetries < 1 || in.MaxRetries > 10 {
		return healthMonitor{}, errInvalidInput("max_retries")
	}
	maxRetriesDown := defaultHMMaxRetriesDown
	if in.MaxRetriesDown != nil {
		if *in.MaxRetriesDown < 1 || *in.MaxRetriesDown > 10 {
			return healthMonitor{}, errInvalidInput("max_retries_down")
		}
		maxRetriesDown = *in.MaxRetriesDown
	}
	monitorPort := 0
	if in.MonitorPort != nil {
		if *in.MonitorPort < 1 || *in.MonitorPort > 65535 {
			return healthMonitor{}, errInvalidInput("monitor_port")
		}
		monitorPort = *in.MonitorPort
	}

	httpMethod := ""
	urlPath := ""
	expectedCodes := ""
	domainName := ""

	if !hmIsHTTPFamily(in.Type) {
		if in.HTTPMethod != nil && *in.HTTPMethod != "" {
			return healthMonitor{}, errInvalidInput("http_method")
		}
		if in.URLPath != nil && *in.URLPath != "" {
			return healthMonitor{}, errInvalidInput("url_path")
		}
		if in.ExpectedCodes != nil && *in.ExpectedCodes != "" {
			return healthMonitor{}, errInvalidInput("expected_codes")
		}
		if in.DomainName != nil && *in.DomainName != "" {
			return healthMonitor{}, errInvalidInput("domain_name")
		}
	} else {
		if in.HTTPMethod != nil && *in.HTTPMethod != "" {
			if !hmValidHTTPMethod(*in.HTTPMethod) {
				return healthMonitor{}, errInvalidInput("http_method")
			}
			httpMethod = *in.HTTPMethod
		} else if in.Type == "HTTP" || in.Type == "HTTPS" {
			httpMethod = "GET"
		}

		if in.URLPath != nil && *in.URLPath != "" {
			if !hmValidURLPath(*in.URLPath) {
				return healthMonitor{}, errInvalidInput("url_path")
			}
			urlPath = *in.URLPath
		} else if in.Type == "HTTP" || in.Type == "HTTPS" {
			urlPath = "/"
		}

		switch {
		case in.ExpectedCodes != nil && *in.ExpectedCodes != "":
			if !hmValidExpectedCodes(*in.ExpectedCodes) {
				return healthMonitor{}, errInvalidInput("expected_codes")
			}
			expectedCodes = *in.ExpectedCodes
		case in.Type == "GRPC":
			expectedCodes = "0"
		default:
			expectedCodes = "200"
		}

		if in.DomainName != nil && *in.DomainName != "" {
			if !hmValidDomainName(*in.DomainName) {
				return healthMonitor{}, errInvalidInput("domain_name")
			}
			domainName = *in.DomainName
		}
	}

	adminUp := true
	if in.AdminStateUp != nil {
		adminUp = *in.AdminStateUp
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.pools(t).Get(ctx, in.PoolID)
	if errors.Is(err, store.ErrNotFound) {
		return healthMonitor{}, errNotFound("pool", in.PoolID)
	}
	if err != nil {
		return healthMonitor{}, err
	}
	if p.HealthMonitorID != "" {
		return healthMonitor{}, errConflict("The pool already has a health monitor.")
	}
	if !hmPoolProtocolAllowed(p.Protocol, in.Type) {
		return healthMonitor{}, errInvalidInput("type")
	}
	if p.AnyPortEnable && monitorPort == 0 {
		return healthMonitor{}, errInvalidInput("monitor_port")
	}

	now := s.nowUTC()
	hm := healthMonitor{
		ID:             s.ids.UUID(),
		PoolID:         p.ID,
		Name:           in.Name,
		Type:           in.Type,
		Delay:          in.Delay,
		Timeout:        in.Timeout,
		MaxRetries:     in.MaxRetries,
		MaxRetriesDown: maxRetriesDown,
		MonitorPort:    monitorPort,
		HTTPMethod:     httpMethod,
		URLPath:        urlPath,
		ExpectedCodes:  expectedCodes,
		DomainName:     domainName,
		AdminStateUp:   adminUp,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.healthMonitors(t).Create(ctx, hm.ID, hm); err != nil {
		return healthMonitor{}, err
	}

	_, err = s.pools(t).Update(ctx, p.ID, func(cur *pool) error {
		cur.HealthMonitorID = hm.ID
		cur.UpdatedAt = now
		return nil
	})
	if err != nil {
		_ = s.healthMonitors(t).Delete(ctx, hm.ID)
		return healthMonitor{}, err
	}
	return hm, nil
}

func (s *Service) getHealthMonitor(ctx context.Context, t Tenant, id string) (healthMonitor, error) {
	hm, err := s.healthMonitors(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return healthMonitor{}, errNotFound("healthmonitor", id)
	}
	if err != nil {
		return healthMonitor{}, err
	}
	return hm, nil
}

func (s *Service) listHealthMonitors(ctx context.Context, t Tenant, f listHealthMonitorsFilter) ([]healthMonitor, pageInfo, error) {
	all, err := s.healthMonitors(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}

	var poolEP map[string]string
	if len(f.EnterpriseProjectIDs) > 0 {
		pools, err := s.pools(t).List(ctx, nil)
		if err != nil {
			return nil, pageInfo{}, err
		}
		poolEP = make(map[string]string, len(pools))
		for _, p := range pools {
			poolEP[p.ID] = p.EnterpriseProjectID
		}
	}

	filtered := make([]healthMonitor, 0, len(all))
	for _, hm := range all {
		if !matchesAny(f.IDs, hm.ID) {
			continue
		}
		if !matchesAny(f.Names, hm.Name) {
			continue
		}
		if !matchesAny(f.Types, hm.Type) {
			continue
		}
		if len(f.MonitorPorts) > 0 && !slices.Contains(f.MonitorPorts, hm.MonitorPort) {
			continue
		}
		if !matchesAny(f.DomainNames, hm.DomainName) {
			continue
		}
		if len(f.Delays) > 0 && !slices.Contains(f.Delays, hm.Delay) {
			continue
		}
		if len(f.Timeouts) > 0 && !slices.Contains(f.Timeouts, hm.Timeout) {
			continue
		}
		if len(f.MaxRetries) > 0 && !slices.Contains(f.MaxRetries, hm.MaxRetries) {
			continue
		}
		if len(f.MaxRetriesDown) > 0 && !slices.Contains(f.MaxRetriesDown, hm.MaxRetriesDown) {
			continue
		}
		if f.AdminStateUp != nil && hm.AdminStateUp != *f.AdminStateUp {
			continue
		}
		if !matchesAny(f.ExpectedCodes, hm.ExpectedCodes) {
			continue
		}
		if !matchesAny(f.URLPaths, hm.URLPath) {
			continue
		}
		if !matchesAny(f.HTTPMethods, hm.HTTPMethod) {
			continue
		}
		if len(f.EnterpriseProjectIDs) > 0 {
			ep := poolEP[hm.PoolID]
			if ep == "" {
				ep = defaultEnterpriseProjectID
			}
			if !inEPList(f.EnterpriseProjectIDs, ep) {
				continue
			}
		}
		filtered = append(filtered, hm)
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].ID < filtered[j].ID })
	return poolPaginate(filtered, func(hm healthMonitor) string { return hm.ID }, f.Page, f.PageReverse)
}

func (s *Service) updateHealthMonitor(ctx context.Context, t Tenant, id string, in updateHealthMonitorInput) (healthMonitor, error) {
	if in.Name != nil && !validName(*in.Name) {
		return healthMonitor{}, errInvalidInput("name")
	}
	if in.Type != nil && !hmValidType(*in.Type) {
		return healthMonitor{}, errInvalidInput("type")
	}
	if in.Delay != nil && (*in.Delay < 1 || *in.Delay > 50) {
		return healthMonitor{}, errInvalidInput("delay")
	}
	if in.Timeout != nil && *in.Timeout < 1 {
		return healthMonitor{}, errInvalidInput("timeout")
	}
	if in.MaxRetries != nil && (*in.MaxRetries < 1 || *in.MaxRetries > 10) {
		return healthMonitor{}, errInvalidInput("max_retries")
	}
	if in.MaxRetriesDown != nil && (*in.MaxRetriesDown < 1 || *in.MaxRetriesDown > 10) {
		return healthMonitor{}, errInvalidInput("max_retries_down")
	}
	if in.MonitorPort.Set && in.MonitorPort.Value != nil {
		if *in.MonitorPort.Value < 1 || *in.MonitorPort.Value > 65535 {
			return healthMonitor{}, errInvalidInput("monitor_port")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	hm, err := s.healthMonitors(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return healthMonitor{}, errNotFound("healthmonitor", id)
	}
	if err != nil {
		return healthMonitor{}, err
	}

	p, poolErr := s.pools(t).Get(ctx, hm.PoolID)
	hasPool := poolErr == nil
	if poolErr != nil && !errors.Is(poolErr, store.ErrNotFound) {
		return healthMonitor{}, poolErr
	}

	effType := hm.Type
	if in.Type != nil {
		if hasPool && !hmPoolProtocolAllowed(p.Protocol, *in.Type) {
			return healthMonitor{}, errInvalidInput("type")
		}
		effType = *in.Type
	}

	if !hmIsHTTPFamily(effType) {
		if in.HTTPMethod != nil && *in.HTTPMethod != "" {
			return healthMonitor{}, errInvalidInput("http_method")
		}
		if in.URLPath != nil && *in.URLPath != "" {
			return healthMonitor{}, errInvalidInput("url_path")
		}
		if in.ExpectedCodes != nil && *in.ExpectedCodes != "" {
			return healthMonitor{}, errInvalidInput("expected_codes")
		}
		if in.DomainName.Set && in.DomainName.Value != nil && *in.DomainName.Value != "" {
			return healthMonitor{}, errInvalidInput("domain_name")
		}
		// Clear HTTP-only fields when switching away from HTTP/HTTPS/GRPC.
		if effType != hm.Type {
			hm.HTTPMethod = ""
			hm.URLPath = ""
			hm.ExpectedCodes = ""
			hm.DomainName = ""
		}
	} else {
		if in.HTTPMethod != nil {
			if !hmValidHTTPMethod(*in.HTTPMethod) {
				return healthMonitor{}, errInvalidInput("http_method")
			}
			hm.HTTPMethod = *in.HTTPMethod
		} else if hm.HTTPMethod == "" && (effType == "HTTP" || effType == "HTTPS") {
			hm.HTTPMethod = "GET"
		}

		if in.URLPath != nil {
			if !hmValidURLPath(*in.URLPath) {
				return healthMonitor{}, errInvalidInput("url_path")
			}
			hm.URLPath = *in.URLPath
		} else if hm.URLPath == "" && (effType == "HTTP" || effType == "HTTPS") {
			hm.URLPath = "/"
		}

		if in.ExpectedCodes != nil {
			if !hmValidExpectedCodes(*in.ExpectedCodes) {
				return healthMonitor{}, errInvalidInput("expected_codes")
			}
			hm.ExpectedCodes = *in.ExpectedCodes
		} else if hm.ExpectedCodes == "" {
			if effType == "GRPC" {
				hm.ExpectedCodes = "0"
			} else {
				hm.ExpectedCodes = "200"
			}
		}

		if in.DomainName.Set {
			if in.DomainName.Value == nil {
				hm.DomainName = ""
			} else {
				if !hmValidDomainName(*in.DomainName.Value) {
					return healthMonitor{}, errInvalidInput("domain_name")
				}
				hm.DomainName = *in.DomainName.Value
			}
		}
	}

	if in.MonitorPort.Set {
		nextPort := 0
		if in.MonitorPort.Value != nil {
			nextPort = *in.MonitorPort.Value
		}
		if hasPool && p.AnyPortEnable && nextPort == 0 {
			return healthMonitor{}, errInvalidInput("monitor_port")
		}
		hm.MonitorPort = nextPort
	}

	hm.Type = effType
	if in.Name != nil {
		hm.Name = *in.Name
	}
	if in.Delay != nil {
		hm.Delay = *in.Delay
	}
	if in.Timeout != nil {
		hm.Timeout = *in.Timeout
	}
	if in.MaxRetries != nil {
		hm.MaxRetries = *in.MaxRetries
	}
	if in.MaxRetriesDown != nil {
		hm.MaxRetriesDown = *in.MaxRetriesDown
	}
	if in.AdminStateUp != nil {
		hm.AdminStateUp = *in.AdminStateUp
	}
	hm.UpdatedAt = s.nowUTC()

	if err := s.healthMonitors(t).Put(ctx, hm.ID, hm); err != nil {
		return healthMonitor{}, err
	}
	return hm, nil
}

func (s *Service) deleteHealthMonitor(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hm, err := s.healthMonitors(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("healthmonitor", id)
	}
	if err != nil {
		return err
	}

	now := s.nowUTC()
	if hm.PoolID != "" {
		_, err := s.pools(t).Update(ctx, hm.PoolID, func(cur *pool) error {
			if cur.HealthMonitorID == id {
				cur.HealthMonitorID = ""
				cur.UpdatedAt = now
			}
			return nil
		})
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	if err := s.healthMonitors(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
