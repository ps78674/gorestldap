SERVER_DIR=./examples/rest
VENV_DIR=$(SERVER_DIR)/.venv

VER=$(shell cat VERSION)
LD_FLAGS='-s -w -X "github.com/ps78674/gorestldap/internal/config.VersionString=$(VER)"'
BUILD_DIR=./build
INSTDIR=/opt/gorestldap

venv:
	python -m venv $(VENV_DIR)
	$(VENV_DIR)/bin/pip install -r $(SERVER_DIR)/requirements.txt
server: venv
	$(VENV_DIR)/bin/python $(SERVER_DIR)/manage.py migrate
	$(VENV_DIR)/bin/python $(SERVER_DIR)/manage.py runserver
clean_db:
	rm -f $(SERVER_DIR)/db.sqlite3
clean_server: clean_db
	rm -rf $(VENV_DIR)
clean: 
	rm -rf $(BUILD_DIR)
	rm -f gorestldap.tar.gz
build: 
	mkdir $(BUILD_DIR)
	go build -trimpath -ldflags=$(LD_FLAGS) -buildmode=plugin -o $(BUILD_DIR)/backends/file.so backends/file/main.go
	go build -trimpath -ldflags=$(LD_FLAGS) -buildmode=plugin -o $(BUILD_DIR)/backends/null.so backends/null/main.go
	go build -trimpath -ldflags=$(LD_FLAGS) -buildmode=plugin -o $(BUILD_DIR)/backends/rest.so backends/rest/main.go
	go build -trimpath -ldflags=$(LD_FLAGS) -o $(BUILD_DIR)/gorestldap ./cmd/gorestldap
	install -m 644 config.yaml $(BUILD_DIR)
install: build
	test -d $(INSTDIR) || mkdir -p $(INSTDIR)
	install -d $(INSTDIR)/backends/
	install -m 644 $(BUILD_DIR)/backends/file.so $(INSTDIR)/backends/
	install -m 644 $(BUILD_DIR)/backends/null.so $(INSTDIR)/backends/
	install -m 644 $(BUILD_DIR)/backends/rest.so $(INSTDIR)/backends/
	install -m 755 $(BUILD_DIR)/gorestldap $(INSTDIR)
	install -m 644 $(BUILD_DIR)/config.yaml $(INSTDIR)
tar: build
	tar cfz gorestldap.tar.gz build --transform 's/build/gorestldap/'

.DEFAULT_GOAL = build
