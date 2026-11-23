# Changelog

All notable changes to WP API Key Authentication are recorded here. This
is the only place the full version history is kept; `README.md` only
points here.

## 1.1.3 — 2026-11-24

- This plugin now removes the oEmbed discovery links (and the
  host script) from the page head itself whenever it blocks
  oEmbed — in `require_all` mode, or in allowlist mode without
  a pattern matching `/oembed/1.0/embed`. Deciding whether
  oEmbed is public is this plugin's job, not WP Site
  Hardening's: that plugin only judges its own REST mode now.
  Neither plugin reads the other's settings, so the links are
  shown only when both let oEmbed through.

## 1.1.2 — 2026-11-24

- Added `/oembed/1.0/embed` to the default allowlist, so oEmbed embeds
  of this site's posts work out of the box in allowlist mode. Only
  the embed endpoint is public: `/oembed/1.0/proxy` stays behind a
  key, because it fetches arbitrary external URLs. Sites already
  running an older version keep their stored allowlist unchanged —
  add the route by hand if you want it. In `require_all` mode
  (the default) the allowlist is inactive, so nothing changes there.

## 1.1.1 — 2026-11-24

- Removed the Disable XML-RPC setting and all of its code. XML-RPC is
  now handled by WP Site Hardening
  (https://github.com/hklcf/wp-site-hardening, same author) instead.
  If you had it on, switch on XML-RPC in WP Site Hardening to keep the
  same protection. Any stored `disable_xmlrpc` value is ignored from
  this version and dropped the next time settings are saved.
- Settings page now suggests installing WP Site Hardening, with a link
  to its GitHub page.
- Added `CHANGELOG.md`.

## 1.1.0

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

## 1.0.1

- Fixed deleting a key whose stored name contains percent-encoded
  characters, by using the raw posted value and a urldecoded fallback.

## 1.0.0

- Rewrote key authentication around `determine_current_user`, so a
  valid key sets the WordPress user and public GET requests stay public.
- Keys are bcrypt-hashed, shown once, and deleted by exact stored name.
