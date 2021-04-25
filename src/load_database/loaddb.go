package load_database

import (
	"fmt"
	"log"
	"os"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/michaelzhao577/fafsa-backend/src/models"
)

func LoadDB() *gorm.DB {
	os.Setenv("HOST", "localhost")
	os.Setenv("DBPORT", "5432")
	os.Setenv("USER", "postgres")
	os.Setenv("NAME", "fafsa_users")
	os.Setenv("PASSWORD", "postgres")
	host := os.Getenv("HOST")
	dbPort := os.Getenv("DBPORT")
	user := os.Getenv("USER")
	dbName := os.Getenv("NAME")
	password := os.Getenv("PASSWORD")

	// database connection
	dbURI := fmt.Sprintf("host=%s user=%s dbname=%s	sslmode=disable password=%s port=%s", host, user, dbName, password, dbPort)

	// open connection to db
	db, err := gorm.Open("postgres", dbURI)

	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Successfully connected to database")
	}

	// close connection to db when main func terminates
	// defer db.Close()

	// make migration to the db if they have not already 	been created
	db.AutoMigrate(&models.Credentials{})

	return db
}
