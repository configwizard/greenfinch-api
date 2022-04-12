package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	client2 "github.com/configwizard/gaspump-api/pkg/client"
	container2 "github.com/configwizard/gaspump-api/pkg/container"
	eacl2 "github.com/configwizard/gaspump-api/pkg/eacl"
	"github.com/configwizard/gaspump-api/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/acl"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const usage = `Example

$ ./createContainer -wallets ./sample_wallets/wallet.json
password is password
`

var (
	walletPath = flag.String("wallets", "", "path to JSON wallets file")
	walletAddr = flag.String("address", "", "wallets address [optional]")
	createWallet = flag.Bool("create", false, "create a wallets")
	password = flag.String("password", "", "wallet password")
	permission = flag.String("permission", "", "permissions on container (public)")

)

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	ctx := context.Background()

	if *createWallet {
		secureWallet, err := wallet.GenerateNewSecureWallet(*walletPath, "some account label", *password)
		if err != nil {
			log.Fatal("error generating wallets", err)
		}
		file, _ := json.MarshalIndent(secureWallet, "", " ")
		_ = ioutil.WriteFile(*walletPath, file, 0644)
		log.Printf("created new wallets\r\n%+v\r\n", file)
		os.Exit(0)
	}

	// First obtain client credentials: private key of request owner
	key, err := wallet.GetCredentialsFromPath(*walletPath, *walletAddr, *password)
	if err != nil {
		log.Fatal("can't read credentials:", err)
	}
	w := wallet.GetWalletFromPrivateKey(key)
	log.Println("using account ", w.Address)
	cli, err := client2.NewClient(key, client2.TESTNET)
	if err != nil {
		log.Fatal("can't create NeoFS client:", err)
	}
	var attributes []*container.Attribute
	placementPolicy := `REP 2 IN X 
	CBF 2
	SELECT 2 FROM * AS X
	`

	id, err := container2.Create(ctx, cli, key, placementPolicy, acl.EACLPublicBasicRule, attributes)
	if err != nil {
		log.Fatal(err)
	}
	await30Seconds(func() bool {
		var prmContainerGet client.PrmContainerGet
		prmContainerGet.SetContainer(*id)
		_, err = cli.ContainerGet(ctx, prmContainerGet)
		return err == nil
	})
	fmt.Printf("Container %s has been persisted in side chain\n", id)

	// Step 2: set restrictive extended ACL
	table := eacl2.PutAllowDenyOthersEACL(*id, nil)
	var prmContainerSetEACL client.PrmContainerSetEACL
	prmContainerSetEACL.SetTable(table)

	_, err = cli.ContainerSetEACL(ctx, prmContainerSetEACL)
	if err != nil {
		log.Fatal("eacl was not set")
	}

	await30Seconds(func() bool {
		var prmContainerEACL client.PrmContainerEACL
		prmContainerEACL.SetContainer(*id)
		r, err := cli.ContainerEACL(ctx, prmContainerEACL)
		if err != nil {
			return false
		}
		expected, _ := table.Marshal()
		got, _ := r.Table().Marshal()
		return bytes.Equal(expected, got)
	})
}

func await30Seconds(f func() bool) {
	for i := 1; i <= 30; i++ {
		if f() {
			return
		}

		time.Sleep(time.Second)
	}
	log.Fatal("timeout")
}
