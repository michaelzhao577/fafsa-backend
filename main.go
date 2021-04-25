package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/michaelzhao577/fafsa-backend/src/database"
	"github.com/michaelzhao577/fafsa-backend/src/routes"
)

func main() {
	database.LoadDB()

	router := mux.NewRouter()

	routes.HandleRequests(router)

	log.Fatal(http.ListenAndServe(":8080", router))
}
