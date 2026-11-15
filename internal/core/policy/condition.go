package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Condition operators, as Huawei documents them for IAM 5.0
// (iam_01_1289); classic policies use a subset (iam_01_0019). Both
// sets are accepted in both languages: Huawei's own classic examples use
// operators, such as StringEndWithIfExists, that only the 5.0 table
// lists.
type opKind int

const (
	opString opKind = iota + 1
	opNumber
	opDate
	opBool
	opNull
	opIP
)

type operator struct {
	kind    opKind
	negated bool
	cmp     func(req, pol string) bool
}

var operators = map[string]operator{
	"StringEquals":              {opString, false, func(r, p string) bool { return r == p }},
	"StringNotEquals":           {opString, true, func(r, p string) bool { return r == p }},
	"StringEqualsIgnoreCase":    {opString, false, strings.EqualFold},
	"StringNotEqualsIgnoreCase": {opString, true, strings.EqualFold},
	"StringMatch":               {opString, false, func(r, p string) bool { return glob(p, r) }},
	"StringNotMatch":            {opString, true, func(r, p string) bool { return glob(p, r) }},
	// StringLike is documented as "not recommended" in favour of
	// StringMatch; it is given StringMatch's wildcard semantics.
	"StringLike":         {opString, false, func(r, p string) bool { return glob(p, r) }},
	"StringNotLike":      {opString, true, func(r, p string) bool { return glob(p, r) }},
	"StringStartWith":    {opString, false, hasPrefixFold},
	"StringNotStartWith": {opString, true, hasPrefixFold},
	"StringEndWith":      {opString, false, hasSuffixFold},
	"StringNotEndWith":   {opString, true, hasSuffixFold},

	"NumberEquals":            {opNumber, false, numberCmp(func(c int) bool { return c == 0 })},
	"NumberNotEquals":         {opNumber, true, numberCmp(func(c int) bool { return c == 0 })},
	"NumberLessThan":          {opNumber, false, numberCmp(func(c int) bool { return c < 0 })},
	"NumberLessThanEquals":    {opNumber, false, numberCmp(func(c int) bool { return c <= 0 })},
	"NumberGreaterThan":       {opNumber, false, numberCmp(func(c int) bool { return c > 0 })},
	"NumberGreaterThanEquals": {opNumber, false, numberCmp(func(c int) bool { return c >= 0 })},

	"DateEquals":            {opDate, false, dateCmp(func(c int) bool { return c == 0 })},
	"DateNotEquals":         {opDate, true, dateCmp(func(c int) bool { return c == 0 })},
	"DateLessThan":          {opDate, false, dateCmp(func(c int) bool { return c < 0 })},
	"DateLessThanEquals":    {opDate, false, dateCmp(func(c int) bool { return c <= 0 })},
	"DateGreaterThan":       {opDate, false, dateCmp(func(c int) bool { return c > 0 })},
	"DateGreaterThanEquals": {opDate, false, dateCmp(func(c int) bool { return c >= 0 })},

	"Bool":         {opBool, false, strings.EqualFold},
	"Null":         {opNull, false, nil},
	"IpAddress":    {opIP, false, ipIn},
	"NotIpAddress": {opIP, true, ipIn},
}

// lookupOperator resolves an operator name. Huawei's own examples also
// spell the number operators Numeric…, so that spelling is accepted.
func lookupOperator(name string) (operator, bool) {
	if rest, ok := strings.CutPrefix(name, "Numeric"); ok {
		name = "Number" + rest
	}
	op, ok := operators[name]
	return op, ok
}

type qualifier int

const (
	qualNone qualifier = iota
	qualAll            // ForAllValues
	qualAny            // ForAnyValue
)

type condition struct {
	name     string // as written, for messages
	op       operator
	ifExists bool
	qual     qualifier
	key      string // lower case
	values   []string
	vars     bool
}

// parseConditions reads a Condition element:
// {"Operator": {"key": [values]}}. Classic policies require each value
// set to be a list (IAM.1053).
func parseConditions(raw json.RawMessage, v5 bool) ([]condition, *Error) {
	var byOp map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byOp); err != nil || byOp == nil {
		return nil, errorf(ErrCondition, "Condition must map operators to {key: values}")
	}
	var out []condition
	for name, keys := range byOp {
		c := condition{name: name}
		base := name
		switch {
		case strings.HasPrefix(base, "ForAllValues:"):
			c.qual, base = qualAll, strings.TrimPrefix(base, "ForAllValues:")
		case strings.HasPrefix(base, "ForAnyValue:"):
			c.qual, base = qualAny, strings.TrimPrefix(base, "ForAnyValue:")
		}
		if b, ok := strings.CutSuffix(base, "IfExists"); ok && b != "Null" {
			c.ifExists, base = true, b
		}
		op, ok := lookupOperator(base)
		if !ok {
			e := errorf(ErrOperator, "unknown condition operator %q", name)
			e.Item = name
			return nil, e
		}
		c.op = op
		if len(keys) == 0 {
			return nil, errorf(ErrCondition, "operator %q has no condition keys", name)
		}
		for key, vraw := range keys {
			if key == "" || !strings.Contains(key, ":") {
				e := errorf(ErrConditionKey, "invalid condition key %q", key)
				e.Item = key
				return nil, e
			}
			vals, ok := scalarStrings(vraw, !v5)
			if !ok {
				kind := ErrConditionValue
				if !v5 {
					kind = ErrConditionList
				}
				e := errorf(kind, "the values of %q under %q must be a list of strings", key, name)
				e.Item, e.Operator = key, name
				return nil, e
			}
			k := c
			k.key, k.values = strings.ToLower(key), vals
			k.vars = v5 && valuesHaveVariables(vals)
			if !k.vars {
				if err := checkValues(k.op.kind, vals); err != nil {
					err.Detail = fmt.Sprintf("%q under %q: %s", key, name, err.Detail)
					err.Item, err.Operator = key, name
					return nil, err
				}
			}
			out = append(out, k)
		}
	}
	return out, nil
}

func valuesHaveVariables(vals []string) bool {
	for _, v := range vals {
		if strings.Contains(v, "${") {
			return true
		}
	}
	return false
}

func conditionsHaveVariables(cs []condition) bool {
	for _, c := range cs {
		if c.vars {
			return true
		}
	}
	return false
}

// checkValues checks that policy values suit their operator.
func checkValues(kind opKind, vals []string) *Error {
	for _, v := range vals {
		ok := true
		switch kind {
		case opNumber:
			_, err := strconv.ParseFloat(v, 64)
			ok = err == nil
		case opDate:
			_, ok = parseDate(v)
		case opBool, opNull:
			ok = strings.EqualFold(v, "true") || strings.EqualFold(v, "false")
		case opIP:
			_, ok = parsePrefix(v)
		}
		if !ok {
			e := errorf(ErrConditionValue, "value %q does not suit the operator", v)
			e.Value = v
			return e
		}
	}
	return nil
}

// eval reports whether the condition holds for the request's keys.
func (c condition) eval(keys map[string][]string) bool {
	reqVals, present := keys[c.key]
	pol := c.values
	if c.vars {
		pol = make([]string, 0, len(c.values))
		for _, v := range c.values {
			s, ok := substitute(v, keys)
			if !ok {
				return false
			}
			pol = append(pol, s)
		}
	}

	if c.op.kind == opNull {
		// Null true: the key is absent; false: it is present.
		absent := len(reqVals) == 0
		for _, p := range pol {
			if strings.EqualFold(p, "true") == absent {
				return true
			}
		}
		return false
	}

	if !present {
		switch {
		case c.qual != qualNone:
			// Documented: a missing key makes ForAllValues and
			// ForAnyValue false.
			return false
		case c.ifExists, c.op.negated:
			// Documented: IfExists holds when the key is absent, and a
			// negated operator gives the same result with or without it.
			return true
		}
		return false
	}

	// valueOK says whether one request value satisfies the operator: for
	// a positive operator it matches some policy value; for a negated
	// one it matches none (several values of a negated operator are
	// NOR, as documented).
	valueOK := func(rv string) bool {
		for _, pv := range pol {
			if c.op.cmp(rv, pv) {
				return !c.op.negated
			}
		}
		return c.op.negated
	}
	switch c.qual {
	case qualAll:
		// Every request value must satisfy it; an empty set does.
		for _, rv := range reqVals {
			if !valueOK(rv) {
				return false
			}
		}
		return true
	case qualAny:
		for _, rv := range reqVals {
			if valueOK(rv) {
				return true
			}
		}
		return false
	}
	if c.op.negated {
		for _, rv := range reqVals {
			if !valueOK(rv) {
				return false
			}
		}
		return true
	}
	for _, rv := range reqVals {
		if valueOK(rv) {
			return true
		}
	}
	return false
}

func hasPrefixFold(r, p string) bool {
	return len(r) >= len(p) && strings.EqualFold(r[:len(p)], p)
}

func hasSuffixFold(r, p string) bool {
	return len(r) >= len(p) && strings.EqualFold(r[len(r)-len(p):], p)
}

func numberCmp(ok func(int) bool) func(r, p string) bool {
	return func(r, p string) bool {
		a, err1 := strconv.ParseFloat(r, 64)
		b, err2 := strconv.ParseFloat(p, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		switch {
		case a < b:
			return ok(-1)
		case a > b:
			return ok(1)
		}
		return ok(0)
	}
}

// parseDate reads an ISO 8601 / RFC 3339 time, as both languages
// document, with or without fractional seconds.
func parseDate(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func dateCmp(ok func(int) bool) func(r, p string) bool {
	return func(r, p string) bool {
		a, ok1 := parseDate(r)
		b, ok2 := parseDate(p)
		if !ok1 || !ok2 {
			return false
		}
		return ok(a.Compare(b))
	}
}

// parsePrefix reads an IP address or CIDR range.
func parsePrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

func ipIn(r, p string) bool {
	a, err := netip.ParseAddr(r)
	if err != nil {
		return false
	}
	pre, ok := parsePrefix(p)
	return ok && pre.Contains(a.Unmap())
}
