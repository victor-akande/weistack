// Command check verifies the keys-and-secrets stack with Huawei's Go SDK,
// through WeiStack's -lan proxy with Huawei Cloud's real endpoints, and
// exits non-zero if anything is wrong.
//
// As the operator (step 8), it checks what read-only credentials can see:
//
//	. ./use.sh operator
//	bin/check -project ... -server ... -keypair ... -key-file secrets/bastion.pem -secret ...
//
// the bastion uses the key pair, KPS's fingerprint matches the private
// key Terraform saved, the secret is listed, and its value is refused.
//
// As the administrator (step 9), -inventory reads WeiStack's inventory
// (GET /_weistack/inventory, signed like any API call) and checks that the
// stack's resources are there and related as Huawei Cloud's Config would
// show them.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/signer"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/request"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	csms "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/csms/v1"
	csmsmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/csms/v1/model"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	ecsmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	kps "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kps/v3"
	kpsmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kps/v3/model"
	"golang.org/x/crypto/ssh"
)

var failed int

func check(what string, ok bool, detail string) {
	mark := "ok  "
	if !ok {
		mark, failed = "FAIL", failed+1
	}
	fmt.Printf("%s %-32s %s\n", mark, what, detail)
}

func main() {
	project := flag.String("project", "", "the region's project ID")
	server := flag.String("server", "", "the bastion's ID")
	keypair := flag.String("keypair", "", "the key pair's name")
	keyFile := flag.String("key-file", "", "the private key Terraform saved")
	secret := flag.String("secret", "", "the secret's name")
	inventory := flag.Bool("inventory", false, "read WeiStack's inventory, as the administrator")
	ids := flag.String("ids", "", "with -inventory: type=id pairs that must be listed, comma-separated")
	flag.Parse()

	weistack, err := url.Parse(os.Getenv("WEISTACK"))
	if err != nil || weistack.Host == "" {
		fmt.Fprintln(os.Stderr, "check: set WEISTACK to the cloud machine, for example https://192.168.1.20:8781")
		os.Exit(2)
	}
	if *inventory {
		checkInventory(weistack, *server, *ids)
	} else {
		if *project == "" || *server == "" || *keypair == "" || *keyFile == "" || *secret == "" {
			flag.Usage()
			os.Exit(2)
		}
		checkAsOperator(weistack, *project, *server, *keypair, *keyFile, *secret)
	}
	if failed > 0 {
		os.Exit(1)
	}
	fmt.Println("the stack is as expected")
}

func checkAsOperator(weistack *url.URL, project, server, keypair, keyFile, secret string) {
	region := env("HW_REGION_NAME", "ap-southeast-1")
	port, _ := strconv.Atoi(weistack.Port())
	hc := config.DefaultHttpConfig().
		WithProxy(config.NewProxy().WithSchema(weistack.Scheme).WithHost(weistack.Hostname()).WithPort(port))
	cred, err := basic.NewCredentialsBuilder().
		WithAk(os.Getenv("HW_ACCESS_KEY")).WithSk(os.Getenv("HW_SECRET_KEY")).WithProjectId(project).SafeBuild()
	if err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		os.Exit(2)
	}
	// KPS and CSMS are part of DEW and share KMS's endpoint.
	client := func(b *core.HcHttpClientBuilder, host string) *core.HcHttpClient {
		h, err := b.WithEndpoints([]string{"https://" + host + "." + region + ".myhuaweicloud.com"}).
			WithCredential(cred).WithHttpConfig(hc).SafeBuild()
		if err != nil {
			fmt.Fprintln(os.Stderr, "check:", err)
			os.Exit(2)
		}
		return h
	}
	ecsClient := ecs.NewEcsClient(client(ecs.EcsClientBuilder(), "ecs"))
	kpsClient := kps.NewKpsClient(client(kps.KpsClientBuilder(), "kms"))
	csmsClient := csms.NewCsmsClient(client(csms.CsmsClientBuilder(), "kms"))

	// The bastion was created with the key pair.
	got, err := ecsClient.ShowServer(&ecsmodel.ShowServerRequest{ServerId: server})
	keyName := ""
	if err == nil && got.Server != nil {
		keyName = got.Server.KeyName
	}
	check("bastion uses the key pair", keyName == keypair, fmt.Sprintf("key_name %q %s", keyName, errText(err)))

	// KPS's fingerprint is the one of the private key Terraform saved.
	local, err := fingerprintOf(keyFile)
	check("saved private key", err == nil, errText(err))
	detail, err := kpsClient.ListKeypairDetail(&kpsmodel.ListKeypairDetailRequest{KeypairName: keypair})
	remote, managed := "", false
	if err == nil && detail.Keypair != nil {
		remote = deref(detail.Keypair.Fingerprint)
		managed = deref(detail.Keypair.IsKeyProtection)
	}
	check("KPS fingerprint matches", local != "" && remote == local, remote+" "+errText(err))
	check("KPS keeps the private key", managed, "is_key_protection "+strconv.FormatBool(managed))

	// The secret is listed, but its value is not readable with these
	// credentials: reading it needs KMS's decrypt permission too.
	list, err := csmsClient.ListSecrets(&csmsmodel.ListSecretsRequest{})
	listed := err == nil && list.Secrets != nil && slices.ContainsFunc(*list.Secrets, func(s csmsmodel.Secret) bool {
		return deref(s.Name) == secret
	})
	check("secret listed", listed, errText(err))
	_, err = csmsClient.ShowSecretVersion(&csmsmodel.ShowSecretVersionRequest{SecretName: secret, VersionId: "latest"})
	var denied *sdkerr.ServiceResponseError
	refused := errors.As(err, &denied) && denied.StatusCode == http.StatusForbidden
	detailText := "read"
	if denied != nil {
		detailText = fmt.Sprintf("%d %s", denied.StatusCode, denied.ErrorCode)
	}
	check("secret value refused", refused, detailText)
}

// checkInventory reads the inventory as the administrator: the admin API
// takes the same signature as every API call under -iam=enforce.
func checkInventory(weistack *url.URL, server, ids string) {
	body, err := signedGet(weistack, "/_weistack/inventory")
	if err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		os.Exit(1)
	}
	var inv struct {
		Resources []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Provider  string `json:"provider"`
			Type      string `json:"type"`
			Relations []struct {
				RelationType string `json:"relation_type"`
				ToType       string `json:"to_resource_type"`
				ToID         string `json:"to_resource_id"`
			} `json:"relations"`
		} `json:"resources"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		fmt.Fprintln(os.Stderr, "check: the inventory:", err)
		os.Exit(1)
	}
	byID := map[string]int{}
	for i, r := range inv.Resources {
		byID[r.Provider+"."+r.Type+"="+r.ID] = i
	}
	for _, want := range strings.Split(ids, ",") {
		if want == "" {
			continue
		}
		_, ok := byID[want]
		check("listed "+strings.SplitN(want, "=", 2)[0], ok, strings.SplitN(want, "=", 2)[1])
	}

	// The bastion's relationships, from the bastion's end.
	i, ok := byID["ecs.cloudservers="+server]
	if !ok {
		check("bastion listed", false, server)
		return
	}
	relations := map[string]string{}
	for _, rel := range inv.Resources[i].Relations {
		relations[rel.RelationType+" "+rel.ToType+"="+rel.ToID] = rel.ToID
	}
	for _, want := range strings.Split(ids, ",") {
		typ, id, _ := strings.Cut(want, "=")
		rel := map[string]string{
			"vpc.vpcs":           "isContainedIn",
			"vpc.publicips":      "isAttachedTo",
			"evs.volumes":        "isAttachedTo",
			"vpc.securityGroups": "isAssociatedWith",
		}[typ]
		if rel == "" {
			continue
		}
		_, ok := relations[rel+" "+typ+"="+id]
		check("bastion "+rel+" "+typ, ok, id)
	}
	fmt.Printf("     %d resources in the inventory\n", inv.Count)
}

// signedGet signs a request with the SDK's signer, as an SDK client
// would, and sends it straight to the cloud machine.
func signedGet(weistack *url.URL, path string) ([]byte, error) {
	req := request.NewHttpRequestBuilder().WithEndpoint(weistack.String()).WithPath(path).WithMethod(http.MethodGet).
		AddHeaderParam("Host", weistack.Host).Build()
	headers, err := signer.Sign(req, os.Getenv("HW_ACCESS_KEY"), os.Getenv("HW_SECRET_KEY"))
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest(http.MethodGet, weistack.String()+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d %s (hint: %s)", path, res.StatusCode, body, res.Header.Get("X-WeiStack-Hint"))
	}
	return body, nil
}

func fingerprintOf(path string) (string, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintLegacyMD5(key.PublicKey()), nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	var e *sdkerr.ServiceResponseError
	if errors.As(err, &e) {
		return fmt.Sprintf("(%d %s)", e.StatusCode, e.ErrorCode)
	}
	return "(" + err.Error() + ")"
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
