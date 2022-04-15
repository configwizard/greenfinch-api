package objects

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	client2 "github.com/configwizard/gaspump-api/pkg/client"
	"github.com/configwizard/gaspump-api/pkg/object"
	"github.com/configwizard/greenfinch-api/api/tokens"
	"github.com/configwizard/greenfinch-api/api/utils"
	"github.com/go-chi/chi/v5"
	"github.com/machinebox/progress"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	object2 "github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/token"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func getBearerToken(ctx context.Context, cli *client.Client, cntID cid.ID, ownerPublicKey, serverPublicKey *keys.PublicKey, sigR, sigS big.Int) (*token.BearerToken, error){
	kOwner := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(serverPublicKey))
	signatureData := elliptic.Marshal(elliptic.P256(), &sigR, &sigS)
	table := tokens.PUTAllowDenyOthersEACL(cntID, serverPublicKey) //eacl2.PutAllowDenyOthersEACL(cntID, serverPublicKey)//eacl2.PutAllowDenyOthersEACL(cntID, serverPublicKey)

	//this client can be the actor's client
	bearer := token.NewBearerToken()
	bearer.SetLifetime(utils.GetHelperTokenExpiry(ctx, cli), 0, 0)
	bearer.SetEACLTable(&table)
	bearer.SetOwner(kOwner)

	//now sign the bearer token
	bearer, err := utils.VerifySignature(bearer.ToV2(), signatureData, *ownerPublicKey)
	if err != nil {
		return nil, err
	}
	return bearer, nil
}

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
func GetObjectHead(cli *client.Client, serverPublicKey *keys.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//this is all going to get done regularly and thus should be a middleware
		cntID := cid.ID{}
		err := cntID.Parse(chi.URLParam(r, "containerId"))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		objID := oid.ID{}
		err = objID.Parse(chi.URLParam(r, "objectId"))
		if err != nil {
			log.Println("no object id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()
		ownerPublicKey, err, code := utils.GetPublicKey(ctx)
		if err != nil {
			log.Println("no public key", err)
			http.Error(w, err.Error(), code)
			return
		}

		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}
		bearer, err := getBearerToken(ctx, cli, cntID, ownerPublicKey, serverPublicKey, sigR, sigS)
		if err != nil {
			log.Println("cannot generate bearer token", err)
			http.Error(w, err.Error(), 400)
			return
		}

		var content *object2.Object
		content, err = object.GetObjectMetaData(ctx, cli, objID, cntID, bearer, nil)
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
func ListObjectsInContainer(cli *client.Client, serverPublicKey *keys.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cntID := cid.ID{}
		err := cntID.Parse(chi.URLParam(r, "containerId"))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()
		k, err, code := utils.GetPublicKey(ctx)
		if err != nil {
			log.Println("no public key", err)
			http.Error(w, err.Error(), code)
			return
		}
		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}
		bearer, err := getBearerToken(ctx, cli, cntID, k, serverPublicKey, sigR, sigS)
		if err != nil {
			log.Println("cannot generate bearer token", err)
			http.Error(w, err.Error(), 400)
			return
		}
		var filters = object2.SearchFilters{}
		filters.AddRootFilter()
		oids, err := object.QueryObjects(ctx, cli, cntID, filters, bearer, nil)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		for _, v := range oids {
			fmt.Printf("oid %v", v.String())
		}

		var stringList []string
		for _, v := range oids {
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
func GetObject(cli *client.Client, serverPrivateKey *keys.PrivateKey) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		cntID := cid.ID{}
		err := cntID.Parse(chi.URLParam(r, "containerId"))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		objID := oid.ID{}
		err = objID.Parse(chi.URLParam(r, "objectId"))
		if err != nil {
			log.Println("no object id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()
		k, err, code := utils.GetPublicKey(ctx)
		if err != nil {
			log.Println("no public key", err)
			http.Error(w, err.Error(), code)
			return
		}
		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}
		bearer, err := getBearerToken(ctx, cli, cntID, k, serverPrivateKey.PublicKey(), sigR, sigS)
		if err != nil {
			log.Println("cannot generate bearer token", err)
			http.Error(w, err.Error(), 400)
			return
		}
		serverOwnerID := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(serverPrivateKey.PublicKey()))
		getSession, err := client2.CreateSessionWithObjectGetContext(ctx, cli, serverOwnerID, &cntID, utils.GetHelperTokenExpiry(ctx, cli), &serverPrivateKey.PrivateKey)
		if err != nil {
			log.Fatal(err)
		}

		var content *object2.Object
		content, err = object.GetObjectMetaData(ctx, cli, objID, cntID, bearer, nil)
		if err != nil {
			log.Println("cannot retrieve metadata", err)
			http.Error(w, err.Error(), 502)
			return
		}
		//f, err := os.Create(filepath.Join("/Users/alex.walker", "tmpFile.jpg"))
		//defer f.Close()
		//if err != nil {
		//	log.Fatal(err)
		//}
		c := progress.NewWriter(w)
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			progressChan := progress.NewTicker(ctx, c, int64(content.PayloadSize()), 50*time.Millisecond)
			for p := range progressChan {
				print("time")
				fmt.Printf("\r%v remaining...", p.Remaining().Round(250*time.Millisecond))
			}
		}()

		ioWriter := (io.Writer)(c)
		obj, err := object.GetObject(ctx, cli, objID, cntID, bearer, getSession, &ioWriter)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		wg.Wait()
		fmt.Println("obj", obj.ID())
	}
}

// UploadObject godoc
// @Summary Upload an object
// @Description Upload object, depending on request content type, defines the upload type. Max upload size 32 MB
// @Tags         objects
// @Param        containerId   path      string  true  "The ID of the container to get the object metadata from"
// @Param       publicKey header string true "Public Key"
// @Param       X-r header string true "The bigInt r, that makes up part of the signature"
// @Param       X-s header string true "The bigInt s, that makes up part of the signature"
// @Accept  application/json
// @Param   file formData file true  "choose a file. Set the content type to multipart/form-data"
// @Produce  json
// @Accept  multipart/form-data
// @Produce octet-stream
// @Param   json body Object true "specify the json content. Set the content type to application/json"
// @Success 200 {array} int [45, 21]
// @Failure 400 {object} HTTPClientError
// @Failure 404 {object} HTTPServerError
// @Router /object/{containerId} [post]
func UploadObject(cli *client.Client, serverPrivateKey *keys.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cntID := cid.ID{}
		err := cntID.Parse(chi.URLParam(r, "containerId"))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()
		k, err, code := utils.GetPublicKey(ctx)
		if err != nil {
			log.Println("no public key", err)
			http.Error(w, err.Error(), code)
			return
		}
		kOwner := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(k))
		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}
		bearer, err := getBearerToken(ctx, cli, cntID, k, serverPrivateKey.PublicKey(), sigR, sigS)
		if err != nil {
			log.Println("cannot generate bearer token", err)
			http.Error(w, err.Error(), 400)
			return
		}
		var attributes []*object2.Attribute
		//handle attributes
		parsedAttributes := map[string]string{}
		attributesStr := r.Header.Get("NEOFS-ATTRIBUTES")
		fmt.Println("received attr", attributesStr)
		if attributesStr != "" {
			if err := json.Unmarshal([]byte(attributesStr), &parsedAttributes); err != nil {
				http.Error(w, "invalid attributes"+err.Error(), 400)
				return
			}
		}
		fmt.Printf("parsed attributes %+v\r\n", parsedAttributes)
		for k, v := range parsedAttributes {
			var tmp *object2.Attribute
			tmp.SetKey(k)
			tmp.SetKey(v)
			attributes = append(attributes, tmp)
		}

		//timestamp is reserved
		timeStampAttr := new(object2.Attribute)
		timeStampAttr.SetKey(object2.AttributeTimestamp)
		timeStampAttr.SetValue(strconv.FormatInt(time.Now().Unix(), 10))
		attributes = append(attributes, timeStampAttr)
		contentTypeAttr := new(object2.Attribute)
		contentTypeAttr.SetKey("Content-Type")
		contentTypeAttr.SetValue(r.Header.Get("Content-Type"))

		wg := sync.WaitGroup{}
		var ioReader io.Reader
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			fmt.Println("application/json")
			//in this case, we are just storing the content as json bytes in the object
			//in this case it is expected the FileName was sent as an attribute already
			if _, ok := parsedAttributes[object2.AttributeFileName]; !ok {
				http.Error(w, "no filename specified", 400)
				return
			}
			ioReader = (io.Reader)(r.Body)
		} else if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
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

			fileNameAttr := new(object2.Attribute)
			fileNameAttr.SetKey(object2.AttributeFileName)
			fileNameAttr.SetValue(handler.Filename)
			attributes = append(attributes, fileNameAttr)
			c := progress.NewReader(file)
			wg.Add(1)
			go func() {
				defer wg.Done()
				progressChan := progress.NewTicker(ctx, c, handler.Size, 50*time.Millisecond)
				for p := range progressChan {
					fmt.Printf("\r%v remaining...", p.Remaining().Round(250*time.Millisecond))
				}
			}()
			ioReader = (io.Reader)(c)
		} else {
			fmt.Println("no valid content type")
			http.Error(w, "no valid content type", 502)
			http.Error(w, err.Error(), 400)
			return
		}

		serverOwnerID := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(serverPrivateKey.PublicKey()))
		putSession, err := client2.CreateSessionWithObjectPutContext(ctx, cli, serverOwnerID, cntID, utils.GetHelperTokenExpiry(ctx, cli), &serverPrivateKey.PrivateKey)
		if err != nil {
			fmt.Println("session error", err)
			http.Error(w, err.Error(), 502)
			return
		}
		id, err := object.UploadObject(ctx, cli, cntID, kOwner, attributes, bearer, putSession, &ioReader)
		if err != nil {
			fmt.Println("upload error", err)
			http.Error(w, err.Error(), 502)
			return
		}
		wg.Wait()
		w.Write([]byte(id.String()))
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
func DeleteObject(cli *client.Client, serverPrivateKey *keys.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("chi.", r.RequestURI)
		cntID := cid.ID{}
		err := cntID.Parse(chi.URLParam(r, "containerId"))
		if err != nil {
			log.Println("no container id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		objID := oid.ID{}
		err = objID.Parse(chi.URLParam(r, "objectId"))
		if err != nil {
			log.Println("no object id", err)
			http.Error(w, err.Error(), 400)
			return
		}
		ctx := r.Context()
		k, err, code := utils.GetPublicKey(ctx)
		if err != nil {
			log.Println("no public key", err)
			http.Error(w, err.Error(), code)
			return
		}
		sigR, sigS, err := utils.RetrieveSignatureParts(ctx)
		if err != nil {
			log.Println("cannot generate signature", err)
			http.Error(w, err.Error(), 400)
			return
		}
		bearer, err := getBearerToken(ctx, cli, cntID, k, serverPrivateKey.PublicKey(), sigR, sigS)
		if err != nil {
			log.Println("cannot generate bearer token", err)
			http.Error(w, err.Error(), 400)
			return
		}
		serverOwnerID := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(serverPrivateKey.PublicKey()))
		deleteSession, err := client2.CreateSessionWithContainerDeleteContext(ctx, cli, serverOwnerID, cntID, utils.GetHelperTokenExpiry(ctx, cli), &serverPrivateKey.PrivateKey)
		if err != nil {
			log.Fatal(err)
		}
		res, err := object.DeleteObject(ctx, cli, objID, cntID, bearer, deleteSession)
		if err != nil {
			log.Println("deleting object failed", err)
			http.Error(w, err.Error(), 400)
		}
		marshal, err := json.Marshal(res)
		if err != nil {
			log.Println("failed to marshal response", err)
			http.Error(w, err.Error(), 502)
		}
		//todo, set to 204
		w.Write(marshal)
	}
}
