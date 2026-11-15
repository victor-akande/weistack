// Package policy parses and evaluates Huawei Cloud IAM permission
// documents: classic roles ("Version": "1.0"), classic fine-grained
// policies ("1.1") and IAM 5.0 identity policies ("5.0").
//
// The grammar and evaluation rules are those Huawei documents:
//
//   - Classic: usermanual-iam iam_01_0019 (Policy Syntax) and iam_01_0601
//     (Role Syntax).
//   - IAM 5.0: usermanual-iam5 iam_01_0934 (Identity Policy Syntax) and
//     iam_01_1289 (JSON Element Reference).
//   - Evaluation: productdesc-iam5 iam_01_1260 (How IAM Works): requests
//     are denied by default, an applicable Allow allows, and any
//     applicable Deny overrides every Allow.
//
// A document is parsed once into a [Policy], which is immutable and safe
// for concurrent use, then evaluated against a [Request] with
// [Evaluate].
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Versions of the policy language.
const (
	VersionRole = "1.0" // classic role-based access control
	VersionFine = "1.1" // classic fine-grained policy
	Version5    = "5.0" // IAM 5.0 identity policy
)

// ErrorKind classifies a document error, so that callers can answer
// with the error code their API documents for it.
type ErrorKind int

// Kinds of document error.
const (
	ErrJSON           ErrorKind = iota + 1 // not a JSON object
	ErrVersion                             // missing or unsupported Version
	ErrStatement                           // Statement missing, not a list, or empty
	ErrElement                             // an element not allowed in a statement
	ErrEffect                              // Effect not Allow or Deny
	ErrAction                              // Action/NotAction missing, both set, or not a list of strings
	ErrResource                            // Resource/NotResource malformed
	ErrCondition                           // Condition not an object of operators
	ErrOperator                            // unknown condition operator
	ErrConditionKey                        // invalid condition key
	ErrConditionList                       // a classic condition's values are not a list
	ErrConditionValue                      // a condition value unsuited to its operator
)

// Error is a document that does not follow the grammar of its version.
type Error struct {
	Kind ErrorKind
	// Item is the offending operator, condition key or resource, if any;
	// for ErrConditionValue, Operator and Value say more.
	Item, Operator, Value string
	Detail                string
}

func (e *Error) Error() string { return "policy: " + e.Detail }

func errorf(kind ErrorKind, format string, args ...any) *Error {
	return &Error{Kind: kind, Detail: fmt.Sprintf(format, args...)}
}

// Policy is a parsed document.
type Policy struct {
	version    string
	statements []statement
}

// Version returns the document's language version.
func (p *Policy) Version() string { return p.version }

// classic reports whether the document is in the classic language,
// whose statements also match an action's aliases.
func (p *Policy) classic() bool { return p.version != Version5 }

type statement struct {
	sid     string
	deny    bool
	notAct  bool
	actions []string // lower case
	notRes  bool
	anyRes  bool // no Resource element: every resource
	res     []resourcePattern
	conds   []condition
	vars    bool // resources or condition values use ${...} variables
}

// Parse parses a document. Its Version decides the grammar.
func Parse(doc []byte) (*Policy, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil || top == nil {
		return nil, errorf(ErrJSON, "the document is not a JSON object")
	}
	var version string
	if err := json.Unmarshal(top["Version"], &version); err != nil {
		return nil, errorf(ErrVersion, "Version must be a string")
	}
	switch version {
	case VersionRole, VersionFine:
	case Version5:
		// IAM 5.0 documents hold exactly Version and Statement.
		for k := range top {
			if k != "Version" && k != "Statement" {
				return nil, errorf(ErrElement, "element %q is not allowed in a 5.0 document", k)
			}
		}
	default:
		return nil, errorf(ErrVersion, "unsupported Version %q", version)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(top["Statement"], &raw); err != nil || len(raw) == 0 {
		return nil, errorf(ErrStatement, "Statement must be a non-empty list")
	}
	p := &Policy{version: version, statements: make([]statement, 0, len(raw))}
	for i, r := range raw {
		st, err := parseStatement(version, r)
		if err != nil {
			err.Detail = fmt.Sprintf("statement %d: %s", i, err.Detail)
			return nil, err
		}
		p.statements = append(p.statements, st)
	}
	return p, nil
}

// statementElements are the elements a 5.0 statement may hold.
var statementElements = map[string]bool{
	"Sid": true, "Effect": true, "Action": true, "NotAction": true,
	"Resource": true, "NotResource": true, "Condition": true,
}

func parseStatement(version string, raw json.RawMessage) (statement, *Error) {
	var el map[string]json.RawMessage
	if err := json.Unmarshal(raw, &el); err != nil || el == nil {
		return statement{}, errorf(ErrStatement, "a statement must be an object")
	}
	v5 := version == Version5
	if v5 {
		for k := range el {
			if !statementElements[k] {
				return statement{}, errorf(ErrElement, "element %q is not allowed", k)
			}
		}
	}
	var st statement

	if sid, ok := el["Sid"]; ok && json.Unmarshal(sid, &st.sid) != nil {
		return statement{}, errorf(ErrElement, "Sid must be a string")
	}

	var effect string
	if json.Unmarshal(el["Effect"], &effect) != nil {
		return statement{}, errorf(ErrEffect, "Effect must be Allow or Deny")
	}
	switch {
	case effect == "Allow", !v5 && strings.EqualFold(effect, "allow"):
	case effect == "Deny", !v5 && strings.EqualFold(effect, "deny"):
		st.deny = true
	default:
		return statement{}, errorf(ErrEffect, "Effect must be Allow or Deny, not %q", effect)
	}

	actions, not, err := stringListElement(el, "Action", "NotAction", true)
	if err != nil {
		return statement{}, errorf(ErrAction, "%s", err)
	}
	st.notAct = not
	for _, a := range actions {
		st.actions = append(st.actions, strings.ToLower(a))
	}

	if version == VersionRole {
		// Roles grant actions on every resource, unconditionally.
		st.anyRes = true
		return st, nil
	}

	if e := st.parseResources(el, v5); e != nil {
		return statement{}, e
	}
	if c, ok := el["Condition"]; ok {
		conds, e := parseConditions(c, v5)
		if e != nil {
			return statement{}, e
		}
		st.conds = conds
	}
	st.vars = v5 && (hasVariables(st.res) || conditionsHaveVariables(st.conds))
	return st, nil
}

func (st *statement) parseResources(el map[string]json.RawMessage, v5 bool) *Error {
	_, hasRes := el["Resource"]
	_, hasNot := el["NotResource"]
	if !hasRes && !hasNot {
		st.anyRes = true
		return nil
	}
	if !v5 && hasNot {
		return errorf(ErrResource, "NotResource is not supported in a classic policy")
	}
	if !v5 && hasRes && isObject(el["Resource"]) {
		// The classic object form ({"uri": [...]}) names agencies, which
		// are not resources of the services evaluated here: such a
		// statement matches no service request.
		return nil
	}
	list, not, err := stringListElement(el, "Resource", "NotResource", false)
	if err != nil {
		return errorf(ErrResource, "%s", err)
	}
	st.notRes = not
	for _, r := range list {
		p, ok := parseResourcePattern(r)
		if !ok {
			e := errorf(ErrResource, "resource %q is not a URN or *", r)
			e.Item = r
			return e
		}
		st.res = append(st.res, p)
	}
	return nil
}

func isObject(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && raw[0] == '{'
}

// stringListElement reads whichever of a and b is present (exactly one
// when required) as a non-empty list of non-empty strings. A single
// string is accepted as a list of one, as in IAM 5.0's examples.
func stringListElement(el map[string]json.RawMessage, a, b string, required bool) (list []string, isB bool, err error) {
	rawA, okA := el[a]
	rawB, okB := el[b]
	switch {
	case okA && okB:
		return nil, false, fmt.Errorf("%s and %s cannot both be set", a, b)
	case !okA && !okB:
		if required {
			return nil, false, fmt.Errorf("%s or %s is required", a, b)
		}
		return nil, false, nil
	}
	name, raw := a, rawA
	if okB {
		name, raw, isB = b, rawB, true
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		list = []string{one}
	} else if json.Unmarshal(raw, &list) != nil {
		return nil, false, fmt.Errorf("%s must be a list of strings", name)
	}
	if len(list) == 0 {
		return nil, false, fmt.Errorf("%s must not be empty", name)
	}
	for _, s := range list {
		if s == "" {
			return nil, false, fmt.Errorf("%s holds an empty string", name)
		}
	}
	return list, isB, nil
}

// scalarStrings reads a condition value: a string, number or boolean, or
// a list of them, as strings.
func scalarStrings(raw json.RawMessage, listOnly bool) ([]string, bool) {
	var many []json.RawMessage
	if err := json.Unmarshal(raw, &many); err != nil {
		if listOnly {
			return nil, false
		}
		many = []json.RawMessage{raw}
	}
	out := make([]string, 0, len(many))
	for _, m := range many {
		var v any
		if err := json.Unmarshal(m, &v); err != nil {
			return nil, false
		}
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case bool:
			out = append(out, strconv.FormatBool(x))
		case float64:
			out = append(out, strings.TrimSpace(string(m)))
		default:
			return nil, false
		}
	}
	return out, len(out) > 0
}
