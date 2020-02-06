VER=$(shell cat VERSION)
LD_FLAGS='-s -w -X "main.versionString=$(VER)"'
BUILD_DIR=./build
INSTDIR=/usr/local/bin

clean: 
	rm -rf $(BUILD_DIR)
build: 
	mkdir $(BUILD_DIR)
	go get -u github.com/docopt/docopt-go
	go get -u github.com/ps78674/goldap/message
	go get -u github.com/ps78674/ldapserver
	go get -u github.com/valyala/fasthttp
	go build -ldflags=$(LD_FLAGS) -o $(BUILD_DIR)/gorestldap ./src
install: build
	test -d $(INSTDIR) || mkdir -p $(INSTDIR)
	install -d $(INSTDIR)
	install -m 755 $(BUILD_DIR)/gorestldap $(INSTDIR)

.DEFAULT_GOAL = build
