package main

import (
	"flag"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	iris "github.com/kataras/iris"
	uuid "github.com/satori/go.uuid"
	//jwt "github.com/dgrijalva/jwt-go"
)

var (
	key  = []byte("mysecret key")
	host = flag.String("host", ":8080", "Host to bind to")
)

func main() {

	app := iris.Default()

	app.Get("health", func(ctx iris.Context) {
		ctx.StatusCode(iris.StatusOK)
	})

	app.Get("/ping", func(ctx iris.Context) {
		ctx.JSON(iris.Map{
			"message": "pong",
		})
	})

	app.Post("/login", func(ctx iris.Context) {

		// TODO Validate the provided information

		pid, err := uuid.NewV4()
		if err != nil {
			fmt.Println("UUID generation failed")
			ctx.StatusCode(iris.StatusInternalServerError)
			return
		}

		sid, err := uuid.NewV4()
		if err != nil {
			fmt.Println("SessionId generation failed")
			ctx.StatusCode(iris.StatusInternalServerError)
			return
		}

		token, err := Encode(key, jwt.MapClaims{
			"uuid":       pid,
			"session-id": sid,
		})

		if err != nil {
			fmt.Println("Token signing failed")
			ctx.StatusCode(iris.StatusInternalServerError)
			return
		}

		ctx.JSON(iris.Map{
			"token": token,
		})
	})

	app.Post("/isValid", func(ctx iris.Context) {
		// Fail all validation attempts
		ctx.StatusCode(iris.StatusUnauthorized)
	})

	// listen and serve on http://0.0.0.0:8080.
	app.Run(iris.Addr(*host))
}

func Decode(key []byte, tokenString string) (*jwt.Token, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return key, nil
	})

	return token, err
}

func Encode(key []byte, message jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, message)

	tokenString, err := token.SignedString(key)

	return tokenString, err
}
