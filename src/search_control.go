package main

import (
	"sync"
)

type searchControl struct {
	domainDone bool
	usersDone  bool
	groupsDone bool
	count      int
	sent       int
}

var searchCtlMap = make(map[int]*searchControl)
var searchCtlMutex sync.Mutex

func getSearchControl(id int) (ret *searchControl) {
	searchCtlMutex.Lock()
	defer searchCtlMutex.Unlock()

	if searchCtlMap[id] == nil {
		searchCtlMap[id] = &searchControl{}
	}

	return searchCtlMap[id]
}

func deleteSearchControl(id int) {
	searchCtlMutex.Lock()
	defer searchCtlMutex.Unlock()

	delete(searchCtlMap, id)
}
