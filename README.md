# OurNet push server

A small wake relay for [OurNet](https://github.com/chozabu/ournet). It lets a
friend's device wake a sleeping Android phone through Firebase Cloud Messaging
(FCM), so messages arrive quickly without OurNet keeping a connection open.

- **Wakes only.** A wake is an empty, high-priority data message. The woken
  phone syncs with its friends directly; nothing it receives passes through
  here.
- **Friends only.** A phone grants one wake token to each friend device. The
  server stores only SHA-256 hashes of the tokens, so it never learns who
  anyone's friends are, and a leaked database cannot be used to wake anyone.
  Revoking one friend's token leaves the others working.
- **Rate limited** per grant and per device, so even a friend cannot drain a
  phone's battery.
- PHP 8.1+ with PDO SQLite, OpenSSL and cURL. No Composer and no daemon, so it
  runs on shared hosting (DreamHost and similar).

## What the server knows

Per device: a random ID, the hash of its admin secret, its FCM token, the
token hashes it granted, and when each was last used. It sees the IP address of
whoever calls it. It does not see message content or the friend graph.

## API

Every call is `POST` with a JSON body, and answers JSON. Errors are
`{"error": "..."}`, with `retry` (seconds) on 429.

| Call | Body | Answer |
|---|---|---|
| `/v1/register` | `{fcm}` | 201 `{device, secret}` |
| `/v1/register` | `{fcm, device, secret}` | 200 `{device}`: updates the FCM token and marks the device as seen |
| `/v1/grants` | `{device, secret, replace?, add?, remove?}` | 200 `{grants}`: the new count |
| `/v1/wake` | `{device, token, kind?, call?}` | 202; 403 not allowed; 429 too soon; 410 device gone |
| `/v1/unregister` | `{device, secret}` | 200 |

- `device` is 22 base64url characters and `secret` is 43, both issued by
  `register`. Keep the secret on the device: it is what lets that device change
  its grants.
- `replace`, `add` and `remove` are lists of lowercase hex SHA-256 hashes of
  wake tokens (16 to 128 base64url characters each, chosen by the device).
  `replace` sets the whole list; `add` and `remove` then apply. A change that
  would go over the limit (2,000) is refused as a whole. OurNet sends `replace`
  with its current friend devices whenever that list changes.
- `wake` answers 403 the same way for an unknown device and for a wrong token.
  On 410 the phone uninstalled OurNet or replaced its FCM token, so the sender
  should forget the address.
- `kind` is `wake` (the default: sync), `call` (ring for incoming call `call`,
  an ID of up to 64 base64url characters) or `cancel` (stop ringing for it).
  Calls and cancels skip the per-grant interval, so a call rings straight
  after a message wake and its cancel follows at once; they still count
  toward the hourly cap. They live 30 seconds in FCM and share a collapse
  key, so a call still queued is replaced by its cancel.
- `GET /` answers `{"service":"ournet-push","version":1}`.

Limits (in `config.php`, `limits`): 5 s between wakes through one grant, 120
wakes per device per hour, 300 registrations and admin calls per IP address per
hour. Devices that have not registered or changed grants for 90 days are
forgotten; OurNet re-registers weekly.

## Firebase setup (once)

1. Create a project in the [Firebase console](https://console.firebase.google.com).
2. Add an Android app with package `org.chozabu.ournet` (and
   `org.chozabu.ournet.profile` if you want profile builds to receive wakes).
   Open its `google-services.json` and copy four values into OurNet's
   `app/android/app/src/main/res/values/firebase.xml`:
   `mobilesdk_app_id` → `google_app_id`, `current_key` → `google_api_key`,
   `project_number` → `gcm_defaultSenderId`, `project_id` → `project_id`.
   These identify the app and are not secret.
3. Project settings → Service accounts → Generate new private key. This JSON
   **is** secret: it goes on the server only, never in a repository.

## Deploy on DreamHost

1. In the panel, add the domain `push.chozabu.net` with HTTPS (Let's Encrypt),
   PHP 8.1 or newer, and set its web directory to
   `~/OurNetPushServer/public`.
2. Copy this repository to `~/OurNetPushServer` (git clone, or upload).
3. On the server:

   ```sh
   cd ~/OurNetPushServer
   cp config.example.php config.php
   mkdir -m 700 data
   # upload the service account key as data/service-account.json, then:
   chmod 600 data/service-account.json config.php
   ```

4. Check: `curl https://push.chozabu.net/` answers
   `{"service":"ournet-push","version":1}`.

Only `public/` is served. `config.php` and `data/` sit outside it, and a
`.htaccess` at the root refuses everything in case the root is ever served.

## Tests

```sh
php tests/run.php
```

These run the server against a temporary database with FCM in `log` mode, so
nothing is sent to Google.
