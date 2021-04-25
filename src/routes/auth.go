package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/michaelzhao577/fafsa-backend/src/models"
	"github.com/michaelzhao577/fafsa-backend/src/security"
)

var jwtKey = []byte("secret_key")

type Database struct {
	DB *gorm.DB
}

func (database Database) Login(w http.ResponseWriter, r *http.Request) {
	// create credentials struct
	var storedCredentials models.Credentials
	var givenCredentials models.Credentials

	params := mux.Vars(r)

	// decode credentials from post request body
	err := json.NewDecoder(r.Body).Decode(&givenCredentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	database.DB.First(&storedCredentials, params["username"])

	verification := security.VerifyPassword(storedCredentials.Password, givenCredentials.Password)

	// if lookup fails or passwords don't match -> error
	if verification != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// set expiration time for the JWT
	expirationTime := time.Now().Add(time.Minute * 10)

	// create a claims struct
	claims := &models.Claims{
		Username: givenCredentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// create token string
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// send token string as cookie in http response
	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
}

func Home(w http.ResponseWriter, r *http.Request) {
	// stores the token associated with the request
	cookie, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// store token string
	tokenStr := cookie.Value

	claims := &models.Claims{}

	// extract jwt from tokenstr
	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Hello, %s", claims.Username)))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	// extract token from request cookie
	cookie, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &models.Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// invalid request if token is not close to expiring
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	// otherwise, assign new expiration time to new token
	expirationTime := time.Now().Add(time.Minute * 10)

	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w,
		&http.Cookie{
			Name:    "refresh_token",
			Value:   tokenString,
			Expires: expirationTime,
		})
}

func (database Database) Register(w http.ResponseWriter, r *http.Request) {
	// decode username and password from post request body
	var givenCredentials models.Credentials

	err := json.NewDecoder(r.Body).Decode(&givenCredentials)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashedPassword, _ := security.Hash(givenCredentials.Password)

	givenCredentials.Password = string(hashedPassword)

	createdUser := database.DB.Create(&givenCredentials)

	err = createdUser.Error

	if err != nil {
		json.NewEncoder(w).Encode(err)
	} else {
		w.Write([]byte(fmt.Sprintf("User Created Successfully!")))
	}
}

func (database Database) GetCredentials(w http.ResponseWriter, r *http.Request) {
	var users []models.Credentials

	database.DB.Find(&users)

	json.NewEncoder(w).Encode(users)
}

func HandleRequests(router *mux.Router, db Database) {
	router.HandleFunc("/login", db.Login).Methods("POST")
	router.HandleFunc("/home", Home).Methods("GET")
	router.HandleFunc("/refresh", Refresh).Methods("POST")
	router.HandleFunc("/register", db.Register).Methods("POST")
	router.HandleFunc("/credentials", db.GetCredentials).Methods("GET")
}
