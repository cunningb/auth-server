The Auth Server is a simple [Iris](github.com/kataras/iris) go server that handles username/password authentication.

It is responsible for receiving login details, and returning a valid login token.
Argon2 is used for password hashing. Salts are randomly generated using the crypto package.