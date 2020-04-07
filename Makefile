.DEFAULT_GOAL := binee

update: ## update depedencies
	go get -u

test: ## test all code
	go test ./...

binee: ## builds the binee executable
	cd cmd/binee && go build -o binee

clean: ## clean up
	rm -rf cmd/binee/binee

