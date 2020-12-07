package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var mySigningKey []byte

type User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func init() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET must be set")
	}
	mySigningKey = []byte(secret)
}

func home(w http.ResponseWriter, r *http.Request) {
	claims := r.Header.Get("claims")
	fmt.Fprintf(w, "Home: %s", claims)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Content-Type must be 'application/json'.")
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Bad Request.")
		return
	}

	if user.Name != "user" || user.Password != "secret" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Not Authorized")
		return
	}

	token, err := GenerateJWT(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Server error.")
		return
	}

	resp := map[string]string{}
	resp["token"] = token
	json.NewEncoder(w).Encode(resp)
}

func GenerateJWT(u User) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["user"] = u.Name
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		err = fmt.Errorf("something went wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}

func isAuthorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] == nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Not Authorized"))
			return
		}

		token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("invalid token")
			}
			return mySigningKey, nil
		})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Not Authorized"))
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !token.Valid || !ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Not Authorized"))
			return
		}
		cB, _ := json.Marshal(claims)

		r.Header.Add("claims", string(cB))
		next.ServeHTTP(w, r)
	})
}

func handleRequests() {
	http.Handle("/", isAuthorized(http.HandlerFunc(home)))
	http.Handle("/login", http.HandlerFunc(login))
	fmt.Println("Server listening on port 5000....")
	log.Fatal(http.ListenAndServe(":5000", nil))
}

func main() {
	handleRequests()
}
