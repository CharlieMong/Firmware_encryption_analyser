BINARY   := firmware-analyser
DIST     := dist
LDFLAGS  := -s -w
WIN_LDFLAGS := -s -w -H windowsgui

.PHONY: all clean windows linux darwin-arm64 darwin-amd64 current

all: windows linux darwin-arm64 darwin-amd64

current:
	go build -ldflags="$(LDFLAGS)" -o $(BINARY) .

windows:
	mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go build -ldflags="$(WIN_LDFLAGS)" \
		-o $(DIST)/$(BINARY)-windows-amd64.exe .

linux:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go build -ldflags="$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-linux-amd64 .

darwin-arm64:
	mkdir -p $(DIST)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
		go build -ldflags="$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-darwin-arm64 .

darwin-amd64:
	mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
		go build -ldflags="$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-darwin-amd64 .

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf $(DIST)
