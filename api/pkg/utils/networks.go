package utils

import "github.com/configwizard/greenfinch-api/api/pkg/config"

type Network string

const Mainnet Network = "mainnet"
const Testnet Network = "testnet"
type NetworkData struct{
	Name string
	ID           string
	Address      string
	SidechainRPC []string
	StorageNodes map[string]config.Peer
	RpcNodes     []string
}

var networks = map[Network]NetworkData{
	Mainnet: {
		Name: "Main Net",
		ID:      "mainnet",
		Address: "NNxVrKjLsRkWsmGgmuNXLcMswtxTGaNQLk",
		SidechainRPC: []string{
			"https://rpc1.morph.fs.neo.org:40341",
			"https://rpc2.morph.fs.neo.org:40341",
			"https://rpc3.morph.fs.neo.org:40341",
			"https://rpc4.morph.fs.neo.org:40341",
			"https://rpc5.morph.fs.neo.org:40341",
			"https://rpc6.morph.fs.neo.org:40341",
			"https://rpc7.morph.fs.neo.org:40341",
		},
		StorageNodes: map[string]config.Peer{
			"0": {
				Address: "grpcs://st1.storage.fs.neo.org:8082",
				Priority: 1,
				Weight: 1,
			},
			"1": {
				Address: "grpcs://st2.storage.fs.neo.org:8082",
				Priority: 2,
				Weight: 1,
			},
			"2": {
				Address: "grpcs://st3.storage.fs.neo.org:8082",
				Priority: 3,
				Weight: 1,
			},
			"3": {
				Address: "grpcs://st4.storage.fs.neo.org:8082",
				Priority: 4,
				Weight: 1,
			},
		},
		RpcNodes: []string{
			"https://rpc10.n3.nspcc.ru:10331",
		},
	},
	Testnet: {
		Name: "Test Net",
		ID:      "testnet",
		Address: "NZAUkYbJ1Cb2HrNmwZ1pg9xYHBhm2FgtKV",
		SidechainRPC: []string{
			"https://rpc1.morph.t5.fs.neo.org:51331",
			"https://rpc2.morph.t5.fs.neo.org:51331",
			"https://rpc3.morph.t5.fs.neo.org:51331",
			"https://rpc4.morph.t5.fs.neo.org:51331",
			"https://rpc5.morph.t5.fs.neo.org:51331",
			"https://rpc6.morph.t5.fs.neo.org:51331",
			"https://rpc7.morph.t5.fs.neo.org:51331",
		},
		StorageNodes: map[string]config.Peer{
			"0": {
				Address:  "grpcs://st1.t5.fs.neo.org:8082",
				Priority: 1,
				Weight:   1,
			},
			"1": {
				Address:  "grpcs://st2.t5.fs.neo.org:8082",
				Priority: 2,
				Weight:   1,
			},
			"2": {
				Address:  "grpcs://st3.t5.fs.neo.org:8082",
				Priority: 3,
				Weight:   1,
			},
			"3": {
				Address:  "grpcs://st4.t5.fs.neo.org:8082",
				Priority: 4,
				Weight:   1,
			},
		},
		RpcNodes: []string{
			"https://rpc.t5.n3.nspcc.ru:20331",
		},
	},
}
