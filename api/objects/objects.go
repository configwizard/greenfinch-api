package objects

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	gspool "github.com/configwizard/greenfinch-api/api/pkg/pool"
	"github.com/configwizard/greenfinch-api/api/pkg/tokens"
	"github.com/google/uuid"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/session"

	"github.com/configwizard/greenfinch-api/api/utils"
	"github.com/go-chi/chi/v5"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	v2session "github.com/nspcc-dev/neofs-api-go/v2/session"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"
)


const uriAddr = "grpcs://st1.t5.fs.neo.org:8082"
func isErrAccessDenied(err error) (string, bool) {
	unwrappedErr := errors.Unwrap(err)
	for unwrappedErr != nil {
		err = unwrappedErr
		unwrappedErr = errors.Unwrap(err)
	}
	switch err := err.(type) {
	default:
		return "", false
	case apistatus.ObjectAccessDenied:
		return err.Reason(), true
	case *apistatus.ObjectAccessDenied:
		return err.Reason(), true
	}
}
func BuildBearerToken(table *eacl.Table, lIat, lNbf, lExp uint64, gateKey *keys.PublicKey, sigR, sigS big.Int) (*bearer.Token, error) {
	var userID user.ID
	user.IDFromKey(&userID, (ecdsa.PublicKey)(*gateKey)) //my understanding is the gateKey is who you want to be able to use this key to access containers?

	var bearerToken bearer.Token

	//todo restrict all other users except the gatekey

	bearerToken.SetEACLTable(*table)
	bearerToken.ForUser(userID)
	bearerToken.SetExp(lExp)
	bearerToken.SetIat(lIat)
	bearerToken.SetNbf(lNbf)

	v2signature := new(refs.Signature)
	v2signature.SetScheme(refs.ECDSA_SHA512)

	signatureData := elliptic.Marshal(elliptic.P256(), &sigR, &sigS)
	v2signature.SetSign(signatureData)
	v2signature.SetKey(gateKey.Bytes())

	var bearerV2 acl.BearerToken
 	bearerToken.WriteToV2(&bearerV2)
	bearerV2.SetSignature(v2signature)
	err := bearerToken.ReadFromV2(bearerV2)
	if err != nil {
		return nil, err
	}
	return &bearerToken, nil
}

func BuildObjectSessionToken(lIat, lNbf, lExp uint64, verb session.ObjectVerb, cnrID cid.ID, gateSession *client.ResSessionCreate, gateKey *keys.PublicKey, sigR, sigS big.Int) (*session.Object, error) {

	var tok session.Object
	tok.ForVerb(verb)
	var idSession uuid.UUID
	if err := idSession.UnmarshalBinary(gateSession.ID()); err != nil {
		return nil, err
	}
	// decode session public key
	var keySession neofsecdsa.PublicKey
	if err := keySession.Decode(gateSession.PublicKey()); err != nil {
		return nil, err
	}
	tok.SetAuthKey(&keySession)
	tok.SetID(idSession)
	tok.SetIat(lIat) //is there a way to dynamically get these at runtime see CalculateEpochsForTime commented above. Can this be done?
	tok.SetNbf(lNbf)
	tok.SetExp(lExp)
	tok.BindContainer(cnrID)

	v2signature := new(refs.Signature)
	v2signature.SetScheme(refs.ECDSA_SHA512)

	signatureData := elliptic.Marshal(elliptic.P256(), &sigR, &sigS)
	v2signature.SetSign(signatureData)
	v2signature.SetKey(gateKey.Bytes())

	var sessionV2 v2session.Token
	tok.WriteToV2(&sessionV2)
	err := tok.ReadFromV2(sessionV2)
	if err != nil {
		return nil, err
	}
	return &tok, nil
}


//func getBearerToken(ctx context.Context, cli *client.Client, cntID cid.ID, ownerPublicKey, serverPublicKey *keys.PublicKey, sigR, sigS big.Int) (*token.BearerToken, error){
//	kOwner := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(serverPublicKey))
//	signatureData := elliptic.Marshal(elliptic.P256(), &sigR, &sigS)
//	table := tokens.PUTAllowDenyOthersEACL(cntID, serverPublicKey) //eacl2.PutAllowDenyOthersEACL(cntID, serverPublicKey)//eacl2.PutAllowDenyOthersEACL(cntID, serverPublicKey)
//
//	//this client can be the actor's client
//	bearer := token.NewBearerToken()
//	bearer.SetLifetime(utils.GetHelperTokenExpiry(ctx, cli), 0, 0)
//	bearer.SetEACLTable(&table)
//	bearer.SetOwner(kOwner)
//
//	//now sign the bearer token
//	bearer, err := utils.VerifySignature(bearer.ToV2(), signatureData, *ownerPublicKey)
//	if err != nil {
//		return nil, err
//	}
//
//	return bearer, nil
//}

// GetObjectHead godoc
// @Summary      Get object metadata
// @Description  Returns the metadata/HEAD of an object in a container
// @Tags         objects
// @Param        containerId   path      string  true  "The ID of the container to get the object metadata from"
// @Param        objectId   path      string  true  "The ID of the object to get the metadata of"
// @Param       publicKey header string true "Public Key"
// @Param       X-r header string true "The bigInt r, that makes up part of the signature"
// @Param       X-s header string true "The bigInt s, that makes up part of the signature"
// @Success      200
// @Failure      400  {object}  HTTPClientError
// @Failure      502  {object}  HTTPServerError
// @Router       /object/{containerId}/{objectId} [head]
// @response     default
// @Header       200              {string}  NEOFS-META  "The base64 encoded version of the binary bearer token ready for signing"
func GetObjectHead(serverPrivateKey *keys.PrivateKey, pl pool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//this is all going to get done regularly and thus should be a middleware
		cntID := cid.ID{}
		err := cntID.Decode([]byte(chi.URLParam(r, "containerId")))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		objID := oid.ID{}
		err = objID.Decode([]byte(chi.URLParam(r, "objectId")))
		if err != nil {
			log.Println("no object id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()

		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}
		iAt, exp, err := gspool.TokenExpiryValue(ctx, pl, 100)
		if err != nil {
			log.Println("cannot generate expiration", err)
			http.Error(w, err.Error(), 400)
			return
		}
		//(table *eacl.Table, lIat, lNbf, lExp uint64, gateKey *keys.PublicKey, sigR, sigS big.Int) (*bearer.Token, error) {
		bearer, err := BuildBearerToken(&eacl.Table{}, iAt, iAt, exp, serverPrivateKey.PublicKey(), sigR, sigS)
		if err != nil {
			log.Println("cannot generate bearer token", err)
			http.Error(w, err.Error(), 400)
			return
		}

		content, err := getObjectMetaData(ctx, objID, cntID, *bearer, pl)
		if err != nil {
			log.Println("cannot retrieve metadata", err)
			http.Error(w, err.Error(), 502)
			return
		}
		response, err := content.MarshalJSON()
		if err != nil {
			log.Println("cannot marhsal metadata", err)
			http.Error(w, err.Error(), 502)
			return
		}
		rEnc := b64.StdEncoding.EncodeToString(response)
		w.Header().Set("NEOFS-META", rEnc)
	}
}

func getObjectMetaData(ctx context.Context, objectID oid.ID, containerID cid.ID, bearer bearer.Token, pl pool.Pool) (object.Object, error) {

	var addr oid.Address
	addr.SetContainer(containerID)
	addr.SetObject(objectID)

	var prmHead pool.PrmObjectHead
	prmHead.SetAddress(addr)
	prmHead.UseBearer(bearer)

	hdr, err := pl.HeadObject(ctx, prmHead)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			fmt.Printf("%w: %s\r\n", err, reason)
			return object.Object{}, err
		}
		fmt.Errorf("read object header via connection pool: %w", err)
		return object.Object{}, err
	}
	return hdr, nil
}

// ListObjectsInContainer godoc
// @Summary      Lists all the objects in a container
// @Description  Returns the IDs of all the objects in the specified container
// @Tags         objects
// @Param        containerId   path      string  true  "The ID of the container to get the object metadata from"
// @Param       publicKey header string true "Public Key"
// @Param       X-r header string true "The bigInt r, that makes up part of the signature"
// @Param       X-s header string true "The bigInt s, that makes up part of the signature"
// @Success      200  {array}	string
// @Failure      400  {object}  HTTPClientError
// @Failure      502  {object}  HTTPServerError
// @Router       /object/{containerId}/ [get]
func ListObjectsInContainer(serverPrivateKey *keys.PrivateKey, pl pool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cntID cid.ID
		err := cntID.Decode([]byte(chi.URLParam(r, "containerId")))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}

		ctx := r.Context()
		//k, err, code := utils.GetPublicKey(ctx)
		//if err != nil {
		//	log.Println("no public key", err)
		//	http.Error(w, err.Error(), code)
		//	return
		//}
		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}
		iAt, exp, err := gspool.TokenExpiryValue(ctx, pl, 100)
		if err != nil {
			log.Println("cannot generate expiration", err)
			http.Error(w, err.Error(), 400)
			return
		}
		bearer, err := BuildBearerToken(&eacl.Table{}, iAt, iAt, exp, serverPrivateKey.PublicKey(), sigR, sigS)
		if err != nil {
			log.Println("cannot generate bearer token", err)
			http.Error(w, err.Error(), 400)
			return
		}
		prms := pool.PrmObjectSearch{}
		prms.UseBearer(*bearer)

		prms.SetContainerID(cntID)
		filters := object.SearchFilters{}
		filters.AddRootFilter()
		prms.SetFilters(filters)

		objects, err := pl.SearchObjects(ctx, prms)
		if err != nil {
			log.Println("cannot search for objects", err)
			http.Error(w, err.Error(), 400)
			return
		}
		var list []oid.ID
		if err = objects.Iterate(func(id oid.ID) bool {
			list = append(list, id)
			return false
		}); err != nil {
			log.Println("error listing objects %s\r\n", err)
			http.Error(w, err.Error(), 400)
			return
		}
		var stringList []string
		for _, v := range list {
			stringList = append(stringList, v.String())
		}
		marshal, err := json.Marshal(stringList)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		w.Write(marshal)
	}
}

type Object struct {
	Attributes map[string]string
	Content []byte
}
// GetObject godoc
// @Summary      Gets the body of an object
// @Description  Returns the body of the object requested in either binary or JSON format
// @Tags         objects
// @Param        containerId   path      string  true  "The ID of the container to get the object metadata from"
// @Param        objectId   path      string  true  "The ID of the object to get the metadata of"
// @Param       publicKey header string true "Public Key"
// @Param       X-r header string true "The bigInt r, that makes up part of the signature"
// @Param       X-s header string true "The bigInt s, that makes up part of the signature"
// @Success      200  {object} Object
// @Produce octet-stream
// @Failure      400  {object}  HTTPClientError
// @Failure      502  {object}  HTTPServerError
// @Router       /object/{containerId}/{objectId} [get]
func GetObject(serverPrivateKey *keys.PrivateKey, pl pool.Pool) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		var cntID cid.ID
		err := cntID.Decode([]byte(chi.URLParam(r, "containerId")))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		objID := oid.ID{}
		err = objID.Decode([]byte(chi.URLParam(r, "objectId")))
		if err != nil {
			log.Println("no object id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()
		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}

		iAt, exp, err := gspool.TokenExpiryValue(ctx, pl, 100)
		if err != nil {
			log.Println("cannot generate expiration", err)
			http.Error(w, err.Error(), 400)
			return
		}

		var addr oid.Address
		addr.SetContainer(cntID)
		addr.SetObject(objID)

		prmCli := client.PrmInit{}
		prmCli.SetDefaultPrivateKey(serverPrivateKey.PrivateKey)
		var prmDial client.PrmDial
		prmDial.SetServerURI(uriAddr)
		cli := client.Client{}
		cli.Init(prmCli)
		cli.Dial(prmDial)

		prmSession := client.PrmSessionCreate{}
		prmSession.UseKey(serverPrivateKey.PrivateKey)
		prmSession.SetExp(exp)
		resSession, err := cli.SessionCreate(ctx, prmSession)
		if err != nil {
			log.Println("cannot create session", err)
			http.Error(w, err.Error(), 400)
			return
		}

		sc, err := BuildObjectSessionToken(iAt, iAt, exp, session.VerbObjectGet, cntID, resSession, serverPrivateKey.PublicKey(), sigR, sigS)
		if err != nil {
			log.Println("error creating session token to create a container", err)
			http.Error(w, err.Error(), 400)
			return
		}
		getInit := client.PrmObjectGet{}
		getInit.WithinSession(*sc)
		getInit.FromContainer(cntID)

		getInit.ByID(objID)
		dstObject := &object.Object{}
		objReader, err := cli.ObjectGetInit(ctx, getInit)
		if err != nil {
			log.Println("error creating object reader ", err)
			http.Error(w, err.Error(), 400)
			return
		}
		if !objReader.ReadHeader(dstObject) {
			res, err := objReader.Close()
			if err != nil {
				log.Println("could not close object reader ", err)
				http.Error(w, err.Error(), 400)
				return
			}
			log.Println("res for failure to read header ", res.Status())
			http.Error(w, err.Error(), 400)
			return
		}
		buf := make([]byte, 1024)
		for {
			n, err := objReader.Read(buf)
			// get total size from object header and update progress bar based on n bytes received
			if errors.Is(err, io.EOF) {
				fmt.Println("end of file")
				break
			}
			if _, err := w.Write(buf[:n]); err != nil {
				fmt.Println("error writing buffer ", err)
				break
			}
		}
		res, err := objReader.Close()
		if err != nil {
			log.Println("res for failure to read header ", res.Status())
			http.Error(w, err.Error(), 400)
		}
		return
	}
}

// UploadObject godoc
// @Summary Upload an object
// @Description Upload object - send content as multipart/form data in the body of the request
// @Tags         objects
// @Param        containerId   path      string  true  "The ID of the container to get the object metadata from"
// @Param       publicKey header string true "Public Key"
// @Param       X-r header string true "The bigInt r, that makes up part of the signature"
// @Param       X-s header string true "The bigInt s, that makes up part of the signature"
// @Accept  multipart/form-data
// @Produce octet-stream
// @Success 200 {array} int [45, 21]
// @Failure 400 {object} HTTPClientError
// @Failure 404 {object} HTTPServerError
// @Router /object/{containerId} [post]
func UploadObject(serverPrivateKey *keys.PrivateKey, pl pool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cntID cid.ID
		err := cntID.Decode([]byte(chi.URLParam(r, "containerId")))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()
		var userID user.ID
		user.IDFromKey(&userID, (ecdsa.PublicKey)(*serverPrivateKey.PublicKey()))

		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}

		iAt, exp, err := gspool.TokenExpiryValue(ctx, pl, 100)
		if err != nil {
			log.Println("cannot generate expiration", err)
			http.Error(w, err.Error(), 400)
			return
		}
		prmCli := client.PrmInit{}
		prmCli.SetDefaultPrivateKey(serverPrivateKey.PrivateKey)
		var prmDial client.PrmDial
		prmDial.SetServerURI(uriAddr)
		cli := client.Client{}
		cli.Init(prmCli)
		cli.Dial(prmDial)

		prmSession := client.PrmSessionCreate{}
		prmSession.UseKey(serverPrivateKey.PrivateKey)
		prmSession.SetExp(exp)
		resSession, err := cli.SessionCreate(ctx, prmSession)
		if err != nil {
			log.Println("cannot create session", err)
			http.Error(w, err.Error(), 400)
			return
		}
		obj := object.New()
		obj.SetContainerID(cntID)
		obj.SetOwnerID(&userID)

		var attributes []object.Attribute
		//handle attributes
		filtered := map[string]string{}
		attributesStr := r.Header.Get("NEOFS-ATTRIBUTES")
		if attributesStr != "" {
			if err := json.Unmarshal([]byte(attributesStr), &filtered); err != nil {
				http.Error(w, "invalid attributes"+err.Error(), 400)
				return
			}
		}
		for k, v := range filtered {
			var tmp object.Attribute
			tmp.SetKey(k)
			tmp.SetValue(v)
			attributes = append(attributes, tmp)
		}
		var ioReader io.Reader
		fmt.Println("multipart management")
		// Parse our multipart form, 10 << 20 specifies a maximum
		// upload of 10 MB files.
		//10 is the number, and we want to shift that 20 places for 10MB
		//32 << 20 for 32MB
		//128 << 20 for 128 MB
		r.ParseMultipartForm(32 << 20)

		file, handler, err := r.FormFile("file")
		if err != nil {
			fmt.Println("Error Retrieving the File", err)
			http.Error(w, err.Error(), 502)
			return
		}
		defer file.Close()
		fmt.Printf("Uploaded File: %+v\n", handler.Filename)
		fmt.Printf("File Size: %+v\n", handler.Size)
		fmt.Printf("MIME Header: %+v\n", handler.Header)

		var fileNameAttr object.Attribute
		fileNameAttr.SetKey(object.AttributeFileName)
		fileNameAttr.SetValue(handler.Filename)
		attributes = append(attributes, fileNameAttr)

		var timestamp object.Attribute
		timestamp.SetKey(object.AttributeTimestamp)
		timestamp.SetValue(strconv.FormatInt(time.Now().Unix(), 10))
		attributes = append(attributes, timestamp)

		obj.SetAttributes(attributes...)
		ioReader = (io.Reader)(file)
		sc, err := BuildObjectSessionToken(iAt, iAt, exp, session.VerbObjectPut, cntID, resSession, serverPrivateKey.PublicKey(), sigR, sigS)
		if err != nil {
			log.Println("error creating session token to create a container", err)
			http.Error(w, err.Error(), 400)
			return
		}

		putInit := client.PrmObjectPutInit{}
		putInit.WithinSession(*sc)
		objWriter, err := cli.ObjectPutInit(ctx, putInit)
		if !objWriter.WriteHeader(*obj) || err != nil {
			log.Println("error writing object header ", err)
			http.Error(w, err.Error(), 400)
			return
		}
		buf := make([]byte, 1024) // 1 MiB
		for {
			n, err := ioReader.Read(buf)
			if !objWriter.WritePayloadChunk(buf[:n]) {
				break
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}

		res, err := objWriter.Close()
		if err != nil {
			log.Println("error closing object writer ", err)
			http.Error(w, err.Error(), 400)
			return
		}
		objectID := res.StoredObjectID()
		w.Write([]byte(objectID.String()))
		return
	}
}

// DeleteObject godoc
// @Summary Delete an object
// @Description Delete object from container (permanent)
// @Tags         objects
// @Param        containerId   path      string  true  "The ID of the container to get the object metadata from"
// @Param        objectId   path      string  true  "The ID of the object to get the metadata of"
// @Param       publicKey header string true "Public Key"
// @Param       X-r header string true "The bigInt r, that makes up part of the signature"
// @Param       X-s header string true "The bigInt s, that makes up part of the signature"
// @Success 204 {object} string  accepted
// @Failure 400 {object} HTTPClientError
// @Failure 404 {object} HTTPServerError
// @Router /object/{containerId}/{objectId} [delete]
func DeleteObject(serverPrivateKey *keys.PrivateKey, pl pool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("chi.", r.RequestURI)
		var cntID cid.ID
		err := cntID.Decode([]byte(chi.URLParam(r, "containerId")))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}

		objID := oid.ID{}
		err = objID.Decode([]byte(chi.URLParam(r, "objectId")))
		if err != nil {
			log.Println("no object id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()
		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}
		iAt, exp, err := gspool.TokenExpiryValue(ctx, pl, 100)
		if err != nil {
			log.Println("cannot generate expiration", err)
			http.Error(w, err.Error(), 400)
			return
		}
		target := eacl.Target{}
		target.SetRole(eacl.RoleUser)
		target.SetBinaryKeys([][]byte{serverPrivateKey.Bytes()})
		table, err := tokens.AllowDelete(cntID, target)
		if err != nil {
			log.Println("error creating access table ", err)
			http.Error(w, err.Error(), 400)
		}
		bearer, err := BuildBearerToken(&table, iAt, iAt, exp, serverPrivateKey.PublicKey(), sigR, sigS)
		if err != nil {
			log.Println("cannot generate bearer token", err)
			http.Error(w, err.Error(), 400)
			return
		}
		var addr oid.Address
		addr.SetContainer(cntID)
		addr.SetObject(objID)

		var prmDelete pool.PrmObjectDelete
		prmDelete.SetAddress(addr)

		prmDelete.UseBearer(*bearer)
		if err := pl.DeleteObject(ctx, prmDelete); err != nil {
			log.Println("cannot delete object", err)
			http.Error(w, err.Error(), 400)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
}
