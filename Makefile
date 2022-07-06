SERVER_DIR=./example_server
VENV_DIR=$(SERVER_DIR)/.venv

VER=$(shell cat VERSION)
LD_FLAGS='-s -w -X "main.versionString=$(VER)"'
BUILD_DIR=./build
INSTDIR=/usr/local/bin

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
