# Forro

Forro is an end-to-end encrypted contact form application for web browsers.

It is written in pure javascript using the [alpinejs](https://alpinejs.dev/) framework.

It uses [PGP (openpgpjs)](https://openpgpjs.org/) for signatures and encryption.


## Dependencies

* [wala-rust](https://defalsify.org/git/wala-rust/) `v0.1.7` (see `Backend` below)


## Install

* `nvm install 18.8`
* `nvm use 18.8`
* `npm install`


## Run

Simple serve the repository root directory with a web server, e.g. [webfsd](https://github.com/ourway/webfsd)


## User interface

The application consists of only two pages.

### Key unlock screen

Session storage is checked for an existing key from a previous visit. If none is found, a new PGP key is created. Upon key creation, the user chooses whether or not to provide a passphrase to encrypt the key in storage. 

### Main screen

All functionality is contained within a single page.

It contains:

* Application state description
* Descriptions and download links for the client's private key, aswell as the receiver's public key.
* A form with:
	- text area for message content.
	- file attachment button to attach files.
	- option to manually supply name and email to use as identity for the key
* Download link for successfully submitted content.
* Button to delete private key from storage


## Data format

The data is submitted in MIME Multipart format.

The `sha256` of the MIME Multipart part that contains the submitted data is signed by the PGP key, and a MIME signature part is added to the message.

The submitted content can be viewed by any email client application.

The signature can also be verified by any email application that provides this feature, or can of course be separately verified using gnupg tools.


## Backend

### Configuration.

Forro will load settings from `settings.json` in the same HTTP path as the application files are hosted.

The available settings are:

* `remote_pubkey_url`: Relative path to recipient public key
* `data_endpoint`: HTTP address to host that will accept submitted data.
* `help`: `true` to show interactive help
* `dev`: `true` to display debugging information for development
* `email_sender`: `From:` sender address to use on the MIME Multipart message
* `email_sender_name`: `From:` sender name to use on the MIME Multipart message


### Data endpoint

This prototype makes use of the [wala](https://defalsify.org/git/wala-rust/) service, which returns a reference to the content submitted.

The host is defined by the `data_endpoint` settings in the configuration.

The submitted content is signed with the client's PGP key. The reference to the content is a sum of the digest of the content aswell as the key used to sign the content.

See [the wala code](https://defalsify.org/git/wala-rust/file/README.html) for a description on how to submit content in a similar manner using the CLI.


## License

AGPLv3+
