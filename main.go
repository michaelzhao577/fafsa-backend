package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/michaelzhao577/fafsa-backend/src/load_database"
	"github.com/michaelzhao577/fafsa-backend/src/routes"
)

func main() {
	dbPointer := load_database.LoadDB()

	var database = routes.Database{
		DB: dbPointer,
	}

	defer database.DB.Close()

	router := mux.NewRouter()

	routes.HandleRequests(router, database)

	log.Fatal(http.ListenAndServe(":8080", router))
}
