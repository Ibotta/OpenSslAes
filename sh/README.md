# Shell OpenSSL AES-256-CBC

> NOTE: There seems to be some weird thing where this shell program doesn't pass the passphrase in the same way if you use the ```pass:passphrase``` syntax.  It works symmetricly, but not with other tools, even the openssl enc command by hand.

## Usage

```sh
./files.sh enc infile outfile pass:passphrase

./files.sh dec infile outfile pass:passphrase
```

