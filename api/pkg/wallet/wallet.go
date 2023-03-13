package wallet

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	client "github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"strconv"
)

type RPC_NETWORK string
//
//const (
//	RPC_TESTNET RPC_NETWORK = "https://rpc.t5.n3.nspcc.ru:20331/"
//	RPC_MAINNET RPC_NETWORK = "https://rpc.t5.n3.nspcc.ru:20331/"
//)

func GenerateNewWallet(path string) (*wallet.Wallet, error) {
	acc, err := wallet.NewAccount()
	if err != nil {
		return &wallet.Wallet{}, err
	}
	w, err := wallet.NewWallet(path)
	w.AddAccount(acc)
	return w, err
}

func GenerateEphemeralAccount() (*wallet.Account, error) {
	acc, err := wallet.NewAccount()
	if err != nil {
		return nil, err
	}
	return acc, nil
}
func GenerateNewSecureWallet(path, name, password string) (*wallet.Wallet, error) {
	w, err := wallet.NewWallet(path)
	w.CreateAccount(name, password)
	return w, err
}

func RetrieveWallet(path string) (*wallet.Wallet, error) {
	w, err := wallet.NewWalletFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("can't read the wallets: %walletPath", err)
	}
	return w, nil
}
func GetCredentialsFromWallet(address, password string, w *wallet.Wallet) (ecdsa.PrivateKey, error) {
	return getKeyFromWallet(w, address, password)
}
func GetCredentialsFromPath(path, address, password string) (ecdsa.PrivateKey, error) {
	w, err := wallet.NewWalletFromFile(path)
	if err != nil {
		return ecdsa.PrivateKey{}, fmt.Errorf("can't read the wallets: %walletPath", err)
	}

	return getKeyFromWallet(w, address, password)
}
func GetWalletFromPrivateKey(key ecdsa.PrivateKey) *wallet.Account {
	privKey := keys.PrivateKey{PrivateKey: key}
	return wallet.NewAccountFromPrivateKey(&privKey)
}
func UnlockWallet(path, address, password string) (*wallet.Account, error) {
	w, err := wallet.NewWalletFromFile(path)
	if err != nil {
		return nil, err
	}
	var addr util.Uint160
	if len(address) == 0 {
		addr = w.GetChangeAddress()
	} else {
		addr, err = flags.ParseAddress(address)
		if err != nil {
			return nil, fmt.Errorf("invalid address")
		}
	}

	acc := w.GetAccount(addr)
	err = acc.Decrypt(password, w.Scrypt)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

type Nep17Tokens struct {
	Asset  util.Uint160 `json:"asset"`
	Amount uint64       `json:"amount""`
	Symbol string       `json:"symbol"`
	Info   wallet.Token `json:"meta"`
	Error  error        `json:"error"`
}

func GetNep17Balances(walletAddress string, network RPC_NETWORK) (map[string]Nep17Tokens, error) {
	ctx := context.Background()
	// use endpoint addresses of public RPC nodes, e.g. from https://dora.coz.io/monitor
	cli, err := client.New(ctx, string(network), client.Options{})
	if err != nil {
		return map[string]Nep17Tokens{}, err
	}
	err = cli.Init()

	if err != nil {
		return map[string]Nep17Tokens{}, err
	}
	recipient, err := StringToUint160(walletAddress)
	if err != nil {
		return map[string]Nep17Tokens{}, err
	}
	balances, err := cli.GetNEP17Balances(recipient)

	tokens := make(map[string]Nep17Tokens)
	for _, v := range balances.Balances {
		tokInfo := Nep17Tokens{}
		symbol, err := cli.NEP17Symbol(v.Asset)
		if err != nil {
			tokInfo.Error = err
			continue
		}
		tokInfo.Symbol = symbol
		fmt.Println(v.Asset, v.Asset)
		number, err := strconv.ParseUint(v.Amount, 10, 64)
		if err != nil {
			tokInfo.Error = err
			continue
		}
		tokInfo.Amount = number

		info, err := cli.NEP17TokenInfo(v.Asset)
		if err != nil {
			tokInfo.Error = err
			continue
		}
		tokInfo.Info = *info
		tokens[symbol] = tokInfo
	}

	return tokens, nil
}

// getKeyFromWallet fetches private key from neo-go wallets structure
func getKeyFromWallet(w *wallet.Wallet, addrStr, password string) (ecdsa.PrivateKey, error) {
	var (
		addr util.Uint160
		err  error
	)

	if addrStr == "" {
		addr = w.GetChangeAddress()
	} else {
		addr, err = flags.ParseAddress(addrStr)
		if err != nil {
			return ecdsa.PrivateKey{}, fmt.Errorf("invalid wallets address %s: %w", addrStr, err)
		}
	}

	acc := w.GetAccount(addr)
	if acc == nil {
		return ecdsa.PrivateKey{}, fmt.Errorf("invalid wallets address %s: %w", addrStr, err)
	}

	if err := acc.Decrypt(password, keys.NEP2ScryptParams()); err != nil {
		return ecdsa.PrivateKey{}, errors.New("[decrypt] invalid password - " + err.Error())

	}

	return acc.PrivateKey().PrivateKey, nil
}
