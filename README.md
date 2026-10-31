# WP API Key Authentication

API key authentication for the WordPress REST API.

A key is tied to one WordPress user. A valid key signs a request in as
that user, so the request gets exactly that user's permissions. Keys are
stored only as bcrypt hashes and are shown once, when they are generated.

## Installation

1. Copy the `wp-api-key-authentication` folder into `wp-content/plugins/`.
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
does not block it unless you turn this setting on. On the same
**API Keys** admin page, tick **Disable XML-RPC** to block XML-RPC
authentication and methods and to remove the X-Pingback header.

It is off by default, because Jetpack, old mobile apps and pingbacks
depend on XML-RPC. Turning it on will break those tools. It does not
affect the REST API, and it does not delete or replace `xmlrpc.php`
itself: the file is still reachable, so for a hard block, block it at
server level as well (for example in `.htaccess` or Cloudflare).

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

### 1.1.0

- Renamed to WP API Key Authentication, author HKLCF, repository
  https://github.com/hklcf/wp-api-key-authentication. Internal
  prefixes changed, so keys from earlier branded versions do not
  migrate; install as a new plugin and generate new keys.
- Added an optional Disable XML-RPC setting (off by default). When on,
  XML-RPC authentication and methods are blocked and the X-Pingback
  header is removed. This is separate from the REST API settings, and
  it is not a server-level block of `xmlrpc.php`.
- Added access settings: public read, require a key for everything
  (default), or allowlist for public GET routes.
- Added per-key scope: full or read-only.
- Added optional per-key expiry date.
- Added last-used tracking (updated at most once an hour).
- Added optional `X-API-Key` header support, alongside Bearer.
- Added `uninstall.php`: deleting the plugin removes its keys and
  settings.
- Removed legacy-key handling and old-format key support: 1.0.x keys
  must be regenerated (see "Upgrading from 1.0.x" above).
- Removed the urldecode fallback in delete: new keys are hex-only, so
  exact delete is enough, and the old percent-encoded key is gone.

### 1.0.1

- Fixed deleting a key whose stored name contains percent-encoded
  characters, by using the raw posted value and a urldecoded fallback.

### 1.0.0

- Rewrote key authentication around `determine_current_user`, so a
  valid key sets the WordPress user and public GET requests stay public.
- Keys are bcrypt-hashed, shown once, and deleted by exact stored name.

## License

GPLv2 or later. See `LICENSE`.
