
.PHONY: default
default:
	go run api/api.go -wallet=wallets/server_wallet.json -password=password

.PHONY: docs
docs:
	cd api && swag init -g "api.go" && cp docs/swagger.json ../client/docs
