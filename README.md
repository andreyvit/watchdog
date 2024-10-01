# watchdogd

Collects checkins from scripts (e.g. backups), and provides status endpoints returning OKAY if checkin happened within the last N hours, which you can monitor via updown.io or similar.

Install: `go install github.com/andreyvit/watchdogd@latest`

Run: `watchdogd -f /var/run/watchdogd.json -t SECRET -l :8080`

Checkin: `curl -X POST -H 'Authentication: Bearer SECRET' http://127.0.0.1:8080/backups-24h`

Set up monitoring to match OKAY on this URL: `http://127.0.0.1:8080/backups-24h`

Note that keys must end with -99h, -99m or -99s suffixes, where 99 is the number of hours, minutes or seconds to consider the checkin fresh.

View all keys: `http://127.0.0.1:8080/`

[2-clause BSD license](LICENSE).
