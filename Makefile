
.PHONY: default
default:
	go run api/api.go -wallet=wallets/server_wallet.json -password=password

.PHONY: container
container:
	go run api/api.go -wallet=wallets/server_wallet.json -password=password -container

.PHONY: object
object:
	go run api/api.go -wallet=wallets/server_wallet.json -password=password -object -containerID=4f6VTwe6QkCxQrsgBYhJVzLwo5oSzyyJDqmtu2dm7975

.PHONY: docs
docs:
	cd api && swag init -g "api.go" && cp docs/swagger.json ../client/docs
