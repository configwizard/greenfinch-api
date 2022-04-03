package tokens

import (
	"crypto/ecdsa"
	b64 "encoding/base64"
	client2 "github.com/configwizard/gaspump-api/pkg/client"
	"github.com/configwizard/greenfinch-api/api/utils"
	"github.com/go-chi/chi/v5"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	json "github.com/virtuald/go-ordered-json"
	"net/http"
	"time"
)
type Bearer struct {
	CreatedAt time.Time `json:"created_at"`
	Token string `json:"token"`
}

func PUTAllowDenyOthersEACL(containerID cid.ID, allowedPubKey *keys.PublicKey) eacl.Table {
	table := eacl.NewTable()
	table.SetCID(&containerID)

	if allowedPubKey != nil {
		target := eacl.NewTarget()
		target.SetBinaryKeys([][]byte{allowedPubKey.Bytes()})

		allowPutRecord := eacl.NewRecord()
		allowPutRecord.SetOperation(eacl.OperationPut)
		allowPutRecord.SetAction(eacl.ActionAllow)
		allowPutRecord.SetTargets(target)

		table.AddRecord(allowPutRecord)
	}

	target := eacl.NewTarget()
	target.SetRole(eacl.RoleOthers)

	denyPutRecord := eacl.NewRecord()
	denyPutRecord.SetOperation(eacl.OperationPut)
	denyPutRecord.SetAction(eacl.ActionDeny)
	denyPutRecord.SetTargets(target)

	table.AddRecord(denyPutRecord)

	return *table
}
func UnsignedBearerToken(cli *client.Client, serverPublicKey *keys.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		//k, err, code := utils.GetPublicKey(ctx)
		//if err != nil {
		//	http.Error(w, err.Error(), code)
		//	return
		//}

		//this public key should be the public key of the request sender (the server)
		cntID := cid.ID{}
		cntID.Parse(chi.URLParam(r, "containerId"))
		kOwner := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(serverPublicKey))
		table := PUTAllowDenyOthersEACL(cntID, serverPublicKey)//eacl2.PutAllowDenyOthersEACL(cntID, k)
		bearer, err := client2.NewBearerToken(kOwner, utils.GetHelperTokenExpiry(ctx, cli), table, false, nil)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}

		//create a bearer token
		v2Bearer := bearer.ToV2()
		binaryData, err := v2Bearer.GetBody().StableMarshal(nil)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		sEnc := b64.StdEncoding.EncodeToString(binaryData)

		b := Bearer{
			CreatedAt: time.Now(),
			Token:     sEnc,
		}
		bEnc, err := json.Marshal(b)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		w.Write(bEnc)
	}
}
