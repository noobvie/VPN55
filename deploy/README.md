# Deployment assets

nginx vhost templates, systemd units, certbot bootstrap.

**Ordering matters:** write an HTTP-only vhost, reload, run certbot, *then* write
the SSL vhost. A vhost that references a not-yet-existent certificate hard-fails
`nginx -t` and takes every other site on the box down with it.

**Deploy excludes:** any rsync/copy that publishes a web root must exclude `lib/`
and `*.sh`. Shipping installer internals — nginx writers, secret provisioning — to
a public web root has already happened once in a sibling project.
