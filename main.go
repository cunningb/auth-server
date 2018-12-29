/*
	The auth server handles
*/

package main

import (
	"flag"
	"fmt"

	"bytes"

	"encoding/base64"

	"golang.org/x/crypto/argon2"

	jwt "github.com/dgrijalva/jwt-go"
	iris "github.com/kataras/iris"
	uuid "github.com/satori/go.uuid"
	//jwt "github.com/dgrijalva/jwt-go"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

type UserDetails struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserDBDetails struct {
	PlayerID string `db:"pid"`
	Password []byte `db:"pw"`
	Salt     []byte `db:"salt"`
}

var (
	key  = []byte("mysecret key")
	host = flag.String("host", ":8080", "Host to bind to")
)

func main() {
	app := iris.Default()

	app.Logger().Info("Attempting db connection...")
	db, err := sql.Open("mysql", "root:dev@/auth")

	if err != nil {
		app.Logger().Fatal("Failed to connect to database")
		return
	}

	app.Logger().Info("Connected to database")

	defer db.Close()

	app.Get("health", func(ctx iris.Context) {
		ctx.StatusCode(iris.StatusOK)
	})

	app.Get("/ping", func(ctx iris.Context) {
		ctx.JSON(iris.Map{
			"message": "pong",
		})
	})

	app.Post("/login", func(ctx iris.Context) {

		logger := ctx.Application().Logger()

		// Must have been provided with username/password

		// Pull password hash and salt from database for that user
		// Hash the password with the salt, and compare to the db value
		// Return an auth token if succesfull, or 403 if not

		var details UserDetails

		ctx.ReadJSON(&details)

		// Enforce basic username validity. Cannot have a nil/empty username
		if len(details.Username) == 0 {
			logger.Warn("Received invalid username.")
			ctx.StatusCode(iris.StatusUnauthorized)
			return
		}

		// Enforce basic password validity. Cannot have a nil/short password
		if len(details.Password) < 8 {
			logger.Warn("Received invalid password")
			ctx.StatusCode(iris.StatusUnauthorized)
			return
		}

		var dbDetails UserDBDetails

		// TODO Don't do this
		func() {

			stmt, err := db.Prepare("CALL byUsername(?)")

			if err != nil {
				logger.Error("Failed to create statement for user lookup:", err)
				ctx.StatusCode(iris.StatusInternalServerError)
				return
			}

			defer stmt.Close()

			result, err := stmt.Query(details.Username)

			if err != nil {
				logger.Error("User lookup failed:", err)
				ctx.StatusCode(iris.StatusInternalServerError)
				return
			}

			if !result.Next() {
				logger.Infof("Failed to find user %s in database", details.Username)
				ctx.StatusCode(iris.StatusUnauthorized)
				return
			}

			err = result.Scan(&dbDetails)

			if err != nil {
				logger.Error("Error during scan:", err)
			}
		}()

		if dbDetails.Salt == nil || dbDetails.Password == nil {
			logger.Warnf("User %s attempted authentication but has invalid data in storage", details.Username)
			ctx.StatusCode(iris.StatusUnauthorized)
			return
		}

		// Grab values from storage -> Need some storage

		// TODO Validate the provided information

		// Generated: SzmUPyaYR5IxMFJ9AkRf1ntCIZ7Jp52hWpd7yR9+yXvhkMB6aVttlnawS/pDcQW+ZLwnoYnkUChsBPli4VEx+A==
		key := argon2.IDKey([]byte(details.Password), dbDetails.Salt, 1, 64*1024, 4, 64)

		if !bytes.Equal(key, dbDetails.Password) {
			logger.Infof("User %s tried to login with invalid password", details.Username)
			ctx.StatusCode(iris.StatusUnauthorized)
			return
		}

		sid, err := uuid.FromString("041834c8-6290-4acf-804d-747295dcf5bf")
		if err != nil {
			ctx.Application().Logger().Error("SessionId generation failed")
			ctx.StatusCode(iris.StatusInternalServerError)
			return
		}

		if err != nil {
			ctx.Application().Logger().Error("Token signing failed")
			ctx.StatusCode(iris.StatusInternalServerError)
			return
		}

		logger.Infof("Validated login for user %s", details.Username)

		ctx.JSON(iris.Map{
			"uuid":       dbDetails.PlayerID,
			"session-id": sid,
			"salt":       base64.StdEncoding.EncodeToString(dbDetails.Salt),
			"key":        base64.StdEncoding.EncodeToString(key),
			//"token":      token,
		})
	})

	app.Post("/isValid", func(ctx iris.Context) {
		// Fail all validation attempts
		ctx.StatusCode(iris.StatusUnauthorized)

		//ctx.GetHeader(iris.StatusRequestHeaderFieldsTooLarge)
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
