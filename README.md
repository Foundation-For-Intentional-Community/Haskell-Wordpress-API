# FIC Haskell-Wordpress REST API

An experimental Haskell REST API that interfaces with our Wordpress database &
supports user authentication.

The point of this is to get faster API calls with easier development,
customizations, & maintainability.

## Usage

Make a new file called `env.sh` with your configuration data:

```sh
export DB_NAME="<database name>"
export DB_USER="<database user>"
export DB_PASS="<database password>"

export LOGGED_IN_KEY="<wp-config logged_in_key >"
export LOGGED_IN_SALT="<wp-config logged_in_salt >"
export NONCE_KEY="<wp-config nonce_key >"
export NONCE_SALT="<wp-config nonce_salt >"

export SITE_URL="<wp-options siteurl>"
```

Then you can build the server, source this file, & run the server:

```sh
stack build
source env.sh
stack exec fic-wordpres
```


# License

GPL-3.0
