# Keycast

Secure remote signing and permissions for teams using Nostr.

## Overview

Keycast aims to make remote signing and secure key management easy for teams using Nostr. Previous solutions like [nsec.app](https://nsec.app/), [Knox](https://gitlab.com/soapbox-pub/knox), and [Amber](https://github.com/greenart7c3/Amber) are great for individuals, but Keycast is designed for teams. This means that you can collaboratively manage your keys and create policies and permissions to control who can sign and what they can sign.

Keycast is fully open source and will offer both a hosted version (if you don't want to have to manage your own deployment) and options for running your own sovereign instance via Docker, StartOS, or Umbrel.

## Features

- [x] NIP-98 HTTP Auth based web application and API authentication
- [x] Team management (create teams, manage stored keys, manage users, manage policies). Supports multiple teams per user.
- [x] Secure key management (row-level aes-256 encryption, file or aws kms backed key storage)
- [x] Permissions and policies (flexible, extensible permissions model)
- [x] NIP-46 Remote signing for managed keys
- [x] Docker based deployment
- [ ] StartOS service
- [ ] Umbrel app
- [ ] CLI for managing teams, keys, users, and policies

## Testing

Quick testing commands:

```bash
# First time setup
./test-quickstart.sh setup

# Test locally
./test-quickstart.sh local

# Test with Docker
./test-quickstart.sh docker

# Deploy to Google Cloud
./test-quickstart.sh gcloud
```

See [TESTING.md](./TESTING.md) for detailed testing documentation.

## Contributing

Contributions are welcome! Please fork or clone the repository and submit a PR with your changes. Small, well-documented changes are appreciated.

### Contributors

<a href="https://github.com/erskingardner/keycast/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=erskingardner/keycast" />
</a>

### The stack

The `api` subdirectory is a Rust application that uses SQLx for database interactions on a local SQLite database. We use `cargo watch` to run the API in watch mode, make sure to install that if you don't already have it.
- [Rust](https://www.rust-lang.org/)
- [SQLx](https://github.com/launchbadge/sqlx)
- [cargo-watch](https://github.com/watchexec/cargo-watch)

The `web` subdirectory contains a SvelteKit app that uses Bun for bundling and Tailwind for styling.
- [SvelteKit](https://kit.svelte.dev/)
- [Bun](https://bun.sh/)
- [Tailwind](https://tailwindcss.com/)

### Getting Started

1. Clone the repository and install workspace dependencies with `bun install`
1. Install the web app dependencies with `cd web && bun install`
1. Then, from the root directory, generate a master encryption key with `bun run key:generate`. This master key is used to encrypt and decrypt Nostr private keys in the database. These are only decrypted when used and remain encrypted at rest. In the future we hope to support other key storage methods, like AWS KMS.
1. Create a `.env` file in the `/web` directory with the following variables:
    - `VITE_ALLOWED_PUBKEYS` - A comma separated list of pubkeys that are allowed to sign in to the app. This would include your own pubkey for development. This `.env` file is ignored and has no bearing on the docker image.

### Running the dev server (API + Web + Signer)
1. You can now run the dev server with `bun run dev`. We use `concurrently` to run the API and web app in parallel. You'll see the web app start up at `https://localhost:5173` and the API will start up at `http://localhost:3000`. Both apps will output logs to the console and will hotreload on code changes. The signer will also start up and will spawn signing processes for each of your authentications. The signing manager will keep an eye on the authentications and pick up new ones as they come in or remove them if they are removed from the database. It will also attempt to restart signing processes if they crash.

### Managing the database

The database is a local SQLite database. There is a helper command to reset the database (drop, create, and run migrations). More can be added as needed.

- `bun run db:reset` - Reset the database (drop, create, and run migrations)

### Custom Permissions

Keycast is built with a flexible permissions model that allows you to define custom permissions. These permissions are defined in the `core/src/custom_permissions` directory. You can define your own custom permissions by implementing the `CustomPermission` trait which has three methods, `can_encrypt`, `can_decrypt`, and `can_sign`. These methods take in the same arguments as the NIP-46 Request objects and return a boolean.

Each request for one of the matching methods (`sign_event`, `nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, `nip44_decrypt`) will be checked against all the permissions defined in the policy. If the permission is not granted, the request will be denied.

To make your custom permission usable in the app, you'll also need to reference it in three places:
1. The `AVAILABLE_PERMISSIONS` array in `web/src/lib/types.ts`
1. The `AVAILABLE_PERMISSIONS` array in `core/src/custom_permissions/mod.rs`
1. The `to_custom_permission` method in `core/src/types/permission.rs`

## Deployment with Docker

1. ssh into your VM or server where you'll want to run Keycast.
1. Install docker following the instructions for your OS here: https://docs.docker.com/engine/install
1. Clone the repository and navigate to the root directory. `git clone https://github.com/erskingardner/keycast.git && cd keycast`
1. Run the init script with a domain: `bash scripts/init.sh <domain>` (you should provide the domain without the protocol (e.g. `https://`) that you want to use for your Keycast instance)
1. (Optional) If you're going to use the caddy reverse proxy, you'll want to set up a Caddy container on your VM as well. There is an example docker-compose file that you can use to get started: [`caddy-docker-compose-example.yml`](./caddy-docker-compose-example.yml).
1. Build and run the docker image with `sudo docker compose up -d --build`. (If you have trouble with the build step stalling while transforming or "Rendering chunks", this is because Vite is non-deterministic and the build step is likely stuck waiting for a lock on the file system. Just cancel the build and run it again - it can take a few tries to get it to build.)

## Updating the app

To update the app on your server, simply run `git pull` to get the latest changes and then run `sudo docker compose up -d --build` to rebuild and restart the container.

### VM requirements

The running app requires very little resources but in order to build the docker images you'll need at least 2GB of RAM (usually helps to have some swap space set up as well). If you're seeing the following errors when building, try to increase the swap space on your VM or use a larger VM.

`failed to solve: process "/bin/sh -c bun run build" did not complete successfully: exit code: 137`

### Reverse proxy

The included [`docker-compose.yml`](./docker-compose.yml) file provides some caddy labels that a caddy reverse proxy docker conatiner will pick up and use to generate SSL certs and wire up the port forwarding required.

This reqiures that your service is running a caddy proxy container. The included [`caddy-docker-compose-example.yml`](./caddy-docker-compose-example.yml) file can be used to start a caddy proxy container and link it to the keycast network.

## License

[MIT](LICENSE)
