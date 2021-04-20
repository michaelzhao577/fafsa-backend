package main

import (
	"fafsa-backend/src/handlers"
	"log"
	"net/http"
)

func main() {
	handleRequests()
}

func handleRequests() {
	http.HandleFunc("/login", handlers.Login)
	http.HandleFunc("/home", handlers.Home)
	http.HandleFunc("/refresh", handlers.Refresh)
	http.HandleFunc("/register", handlers.Register)
	http.HandleFunc("/users", handlers.GetUsers)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
