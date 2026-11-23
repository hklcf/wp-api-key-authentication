# WP API Key Authentication

API key authentication for the WordPress REST API.

A key is tied to one WordPress user. A valid key signs a request in as
that user, so the request gets exactly that user's permissions. Keys are
stored only as bcrypt hashes and are shown once, when they are generated.

## Installation

1. In WordPress admin, go to Plugins > Add New > Upload Plugin and
   choose the release zip (`wp-api-key-authentication-1.1.2.zip`).
   Or install it by hand: the repository root is the plugin folder,
   so copy its contents into a new
   `wp-content/plugins/wp-api-key-authentication/` folder — there is
   no subfolder to copy out of it.
2. Activate **WP API Key Authentication** in WordPress admin.
3. Open **API Keys** in the admin menu and generate a key for a user who
   can edit posts.
4. Send the key as a Bearer token, or (if enabled in settings) as an
   `X-API-Key` header. Always use HTTPS in production.

```bash
curl -H "Authorization: Bearer YOUR_KEY" \
  https://example.com/wp-json/wp/v2/users/me?context=edit
```

```bash
curl -H "X-API-Key: YOUR_KEY" \
  https://example.com/wp-json/wp/v2/users/me?context=edit
```

Never put a key in a URL query string, and never commit a real key to a
repository.

## Access settings

Settings live on the same **API Keys** admin page. The default mode is
"Require a key for every REST request".

| Mode | What happens to unauthenticated REST requests |
| --- | --- |
| Public read stays public | Public read endpoints stay public, as in WordPress without this plugin. A valid key is still needed to act as a user, and an invalid Bearer key still returns 403. |
| Require a key for every REST request (default) | Every REST request needs a valid key or another WordPress authentication method (for example a logged-in cookie). Unauthenticated reads return 401. A client that sends a key, for example an automation script with its own key, can still read public content through the API. Normal website browsing is not affected. |
| Require a key, except listed routes | GET requests to the routes in the allowlist stay public. Everything else needs a key or another WordPress authentication method. A route ending in `*` matches everything under it, for example `/wp/v2/posts/*`. |

Warning: "Require a key for every REST request" also blocks public apps
and front-ends that read the site through the REST API without a key.
Do not turn it on for a site whose public content is meant to be read
by anonymous visitors, unless those readers are going to send a key.

## XML-RPC

XML-RPC (`xmlrpc.php`) is separate from the REST API, and this plugin
does not touch it. To disable XML-RPC, install
[WP Site Hardening](https://github.com/hklcf/wp-site-hardening)
(same author, download it from GitHub), which disables XML-RPC
(filter + hard 403 + header/link removal) along with feeds, the REST
API and the default login URL. The Disable XML-RPC setting this plugin
used to have was removed in 1.1.1 — see `CHANGELOG.md`.

## Per-key options

- **Scope.** Full access gives the key the linked user's permissions.
  Read-only allows only GET, HEAD and OPTIONS; other methods return 403.
- **Expiry date.** Leave blank for a key that never expires. After its
  expiry date a key returns 403 with `api_key_expired`.
- **Last used.** Shown in the key list. It is updated at most once an
  hour, so a busy key does not cause a database write on every request.

## Upgrading from 1.0.x: breaking change

- This version is deliberately not backward compatible. There is no
  old version in the wild for this GitHub release, so old key formats
  are not supported.
- A key created under 1.0.x has no scope field, so under 1.1.0 it
  returns 403 as an invalid key. Delete it and generate a new key,
  then re-register that new key wherever it is used.
- This renamed release does not migrate keys from earlier branded versions. Install it as a new plugin, generate new keys, and delete the old plugin only after the new keys are working.
- Deleting the plugin (not just deactivating it) removes its keys and
  its settings. Deactivating it leaves them in place.

## Security notes

- Keys are generated with `wp_generate_password()` and stored with
  `password_hash()` (bcrypt). The plain key is never stored.
- An invalid Bearer key returns 403, and an expired key returns 403
  with a different error code, so the two cases are easy to tell apart
  in logs.
- A key is only as safe as the user it is tied to. Give a key to the
  least-privileged user that can do the job, and use a read-only key
  for anything that only needs to read.
- This plugin does not add rate limiting. If the site is exposed to
  the internet, keep a firewall or rate limiter in front of it.

## Changelog

See `CHANGELOG.md` for the full version history.

## License

GPLv2 or later. See `LICENSE`.
