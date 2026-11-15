package policy

import "testing"

// FuzzParse checks that no document crashes the parser or the evaluator.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["obs:bucket:*"],"Resource":["obs:*:*:bucket:*"],"Condition":{"StringEndWithIfExists":{"g:UserName":["x"]}}}]}`,
		`{"Version":"5.0","Statement":[{"Effect":"Deny","NotAction":["iam:*:*"],"NotResource":["iam::${g:DomainId}:user:${g:UserName, 'x'}"],"Condition":{"ForAllValues:StringMatch":{"g:TagKeys":["a*"]},"IpAddress":{"g:SourceIp":"10.0.0.0/8"}}}]}`,
		`{"Version":"1.0","Statement":[{"Effect":"Allow","Action":["*:*:*"]}],"Depends":[]}`,
		`{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Resource":{"uri":["/x"]}}]}`,
	} {
		f.Add(seed, "vpc:vpcs:get", "vpc:r:a:vpc:v")
	}
	f.Fuzz(func(_ *testing.T, doc, action, resource string) {
		p, err := Parse([]byte(doc))
		if err != nil {
			return
		}
		keys := map[string][]string{"g:username": {"alice"}, "g:sourceip": {"10.0.0.1"}, "g:tagkeys": {"a", "b"}}
		_ = Evaluate(Request{Action: action, Aliases: []string{action}, Resources: []string{resource}, Keys: keys}, []Source{{Name: "f", Policy: p}})
		_ = Evaluate(Request{Action: action}, []Source{{Name: "f", Policy: p}})
	})
}
