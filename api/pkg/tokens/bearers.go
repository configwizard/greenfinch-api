package tokens

import (
	"crypto/ecdsa"
	b64 "encoding/base64"
	"encoding/json"
	gspool "github.com/configwizard/greenfinch-api/api/pkg/pool"
	"github.com/configwizard/greenfinch-api/api/pkg/utils"
	"github.com/go-chi/chi/v5"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"log"
	"net/http"
	"time"
)

// see here if you want to convert a time to an epoch https://github.com/nspcc-dev/neofs-s3-gw/blob/master/internal/neofs/neofs.go

type Bearer struct {
	CreatedAt time.Time `json:"created_at"`
	Token string `json:"token"`
}

func PUTAllowDenyOthersEACL(containerID cid.ID, allowedPubKey *keys.PublicKey) eacl.Table {
	table := eacl.NewTable()
	table.SetCID(containerID)

	if allowedPubKey != nil {
		var target eacl.Target
		target.SetBinaryKeys([][]byte{allowedPubKey.Bytes()})

		allowPutRecord := eacl.NewRecord()
		allowPutRecord.SetOperation(eacl.OperationPut)
		allowPutRecord.SetAction(eacl.ActionAllow)
		allowPutRecord.SetTargets(target)

		table.AddRecord(allowPutRecord)
	}

	target := eacl.Target{}
	target.SetRole(eacl.RoleOthers)

	denyPutRecord := eacl.NewRecord()
	denyPutRecord.SetOperation(eacl.OperationPut)
	denyPutRecord.SetAction(eacl.ActionDeny)
	denyPutRecord.SetTargets(target)

	table.AddRecord(denyPutRecord)

	return *table
}
func UnsignedBearerToken(serverPrivateKey *keys.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		storageNodes, err := utils.RetrieveStorageNode(ctx)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), 400)
			return
		}
		pl, err := gspool.GetPool(ctx, serverPrivateKey.PrivateKey, storageNodes)
		if err != nil {
			log.Println("error could not instantiate pool", err)
			http.Error(w, err.Error(), 502)
			return
		}
		iAt, exp, err := gspool.TokenExpiryValue(ctx, *pl, 100)
		if err != nil {
			log.Println("cannot generate expiration", err)
			http.Error(w, err.Error(), 400)
			return
		}
		//this public key should be the public key of the request sender (the server)
		cntID := cid.ID{}
		cntID.Decode([]byte(chi.URLParam(r, "containerId")))
		//kOwner := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(serverPublicKey))
		table := PUTAllowDenyOthersEACL(cntID, serverPrivateKey.PublicKey())//eacl2.PutAllowDenyOthersEACL(cntID, k)
		//func NewBearerToken(tokenReceiver *owner.ID, expire uint64, eaclTable eacl.Table, sign bool, containerOwnerKey *ecdsa.PrivateKey) (*token.BearerToken, error){
		//
		var btoken bearer.Token
		btoken.SetIat(iAt)
		btoken.SetNbf(iAt)
		btoken.SetExp(exp)
		var userID user.ID
		user.IDFromKey(&userID, (ecdsa.PublicKey)(*serverPrivateKey.PublicKey())) //my understanding is the gateKey is who you want to be able to use this key to access containers?

		btoken.ForUser(userID)
		btoken.SetEACLTable(table)

		var bearerV2 acl.BearerToken
		btoken.WriteToV2(&bearerV2)
		binaryData := bearerV2.GetBody().StableMarshal(nil)
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
