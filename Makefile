SERVER_DIR=./example_server
VENV_DIR=$(SERVER_DIR)/.venv

VER=$(shell cat VERSION)
LD_FLAGS='-s -w -X "main.versionString=$(VER)"'
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
build: 
	mkdir $(BUILD_DIR)
	go build -trimpath -ldflags=$(LD_FLAGS) -buildmode=plugin -o $(BUILD_DIR)/file.so plugins/file/main.go
	go build -trimpath -ldflags=$(LD_FLAGS) -buildmode=plugin -o $(BUILD_DIR)/null.so plugins/null/main.go
	go build -trimpath -ldflags=$(LD_FLAGS) -buildmode=plugin -o $(BUILD_DIR)/rest.so plugins/rest/main.go
	go build -trimpath -ldflags=$(LD_FLAGS) -o $(BUILD_DIR)/gorestldap ./src
	install -m 644 config.yaml $(BUILD_DIR)
install: build
	test -d $(INSTDIR) || mkdir -p $(INSTDIR)
	install -d $(INSTDIR)
	install -m 644 $(BUILD_DIR)/file.so $(INSTDIR)
	install -m 644 $(BUILD_DIR)/null.so $(INSTDIR)
	install -m 644 $(BUILD_DIR)/rest.so $(INSTDIR)
	install -m 755 $(BUILD_DIR)/gorestldap $(INSTDIR)
tar: build
	tar cfz gorestldap.tar.gz build --transform 's/build/gorestldap/'

.DEFAULT_GOAL = build
