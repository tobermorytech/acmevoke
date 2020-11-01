ACMEvoke is a simple web service that accepts certificate revocation requests
using the private key of the certificate being revoked, using the [ACME](https://tools.ietf.org/html/rfc8555) protocol.


# Requirements

To run ACMEvoke, you need:

* An installation of Ruby 2.5 or later, and the bundler package management
  tool.

* A [Redis](https://redis.io) server, configured to persist all data.

* A set of issuing CA certificates for which you are willing to accept
  revocation requests.

* An e-mail address to receive the validated notifications of revocation
  requests, and an SMTP server through which to send them.


# Setup

Getting an ACMEvoke server up and running is straightforward.

1. Clone the ACMEvoke git repo, and `cd` into that directory.

1. Run `bundle install --deployment` in the git checkout directory.

1. Put all the issuing CA certificates you wish to accept revocation requests
   for in a single file, one after the other, each in PEM format.

1. Set all the necessary environment variables:

        # This is a single file full of PEM-format certificates which are the
        # direct issuers of the certificates you wish to accept revocation
        # requests for.
        export ACMEVOKE_ISSUER_CERTIFICATES_FILE="/the/path/to/the/certs/file"

        # The host, etc of the Redis server that ACMEvoke will use to store
        # some useful information.
        export ACMEVOKE_REDIS_URL="redis://host:6379"

        # The publicly-accessible URL of the ACMEvoke service; this URL is
        # used to construct URLs given to clients.
        export ACMEVOKE_BASE_URL="https://example.com/acmevoke"

        # The e-mail address from which all the validated revocation requests
        # will be sent.
        export ACMEVOKE_REVOCATION_NOTIFICATION_SENDER="acmevoke@example.com"

        # The address to which e-mail will be sent when a validated
        # revocation request is received by ACMEvoke.
        export ACMEVOKE_REVOCATION_NOTIFICATION_RECIPIENT="revocation@example.com"

        # The mail delivery method to use.  Can be any of "smtp", "sendmail",
        # "file", or "stderr".  For details of each mail delivery method,
        # see the "Mail Delivery Configuration" section, below.
        export ACMEVOKE_MAIL_DELIVERY_METHOD="sendmail"

        # Mail sending configuration.  The available variables depend on the
        # mail delivery method you chose.
        # See the section "Mail Delivery Configuration" below for all the gory details.
        export ACMEVOKE_MAIL_DELIVERY_CONFIG_<var>="value"

1. Start the ACMEvoke server:

        RUBYLIB=lib rackup

1. Configure whatever front-end HTTP proxy listens on the host you specified in `ACMEVOKE_BASE_URL`
   to forward requests for the `ACMEVOKE_BASE_URL` path to the ACMEvoke server.

1. Start reveling in the ACME-based revocation goodness.


## Advanced Configuration

Whilst it is beyond the scope of ACMEvoke itself, there are some things you'll
want to consider when deploying an ACMEvoke instance in production.  These
include:

1. **Load balancing / High Availability**: While ACMEvoke is a relatively
   lightweight service, it's nice if you can handle load spikes and outages
   without everything going pear-shaped.  ACMEvoke itself is (almost) entirely
   stateless; it only keeps a record of recently issued nonces in a Redis
   instance, and clients should be able to recover from lost nonces in the
   unpleasant event of a Redis server blowing up.

1. **Rate-limiting**: To ensure service availability in the face of unpleasantness,
   you should configure appropriate rate limits, along with responding with
   a response in compliance with [RFC8555 section 6.6](https://tools.ietf.org/html/rfc8555#section-6.6).

1. **Monitoring / Incident Handling**: It's probably best if you know what's
   going on inside your ACMEvoke server, and also if it unexpectedly goes away,
   so you'll want to instrument the service using tools of your choice, setup
   external availability monitoring tooling, and feed alerts to your operations
   people to investigate and fix.

1. **Logging**: ACMEvoke spits all its logs to stderr, including any exceptions
   (if they occur).  You probably want to gather those up and put them
   somewhere useful, just in case.

If all that sounds like more trouble than you'd rather go to, a fully-managed
cloud-hosted ACMEvoke service is available, which takes care of all of the above
and more, for a reasonable monthly fee.  Contact
[`sales@tobermorytech.com`](mailto:sales@tobermorytech.com?subject=Hosted+ACMEvoke+inquiry) to find out more.


## Mail Delivery Configuration

There are several methods you can configure to send e-mail from ACMEvoke (because everyone seems to
have their own ideas about how mail should be done).  Each one, naturally, has its own
configuration parameters.  Listed below are the available delivery methods, and
the environment variables that configure each.

### SMTP

```
ACMEVOKE_MAIL_DELIVERY_METHOD="smtp"
```

Causes ACMEvoke to connect to the specified SMTP server and attempt to deliver
all mail through that.

Available configuration environment variables:

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_ADDRESS`** (default: `"localhost"`) -- the name or
  IP address of the SMTP server to connect to.

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_PORT`** (default: `"25"`) -- the TCP port to use
  to connect to the SMTP server.

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_USER_NAME`** (default: unset) /
  **`ACMEVOKE_MAIL_DELIVERY_CONFIG_PASSWORD`** (default: unset) -- if both of
  these variables are set to a non-empty string, then SMTP authentication is
  attempted using these credentials before mail is delivered.

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_AUTH_METHOD`** (default: "plain") sets
  the type of SMTP authentication method to use, if a username and password
  are set.  Valid values are `"plain"`, `"login"`, and `"cram_md5"`.

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS`** (default: `"always"`) the approach
  to TLS that the SMTP connection should use.  Valid values are:

  * `"always"`: negotiate TLS using `STARTTLS`, and refuse to use a server
    that does not advertise support for `STARTTLS`.  This is the safest
    approach, as it prevents MitM downgrade attacks as well as passive
    observation of mail traffic.

  * `"auto"`: negotiate TLS using `STARTTLS` if the server advertises support,
    otherwise proceeed with an unencrypted SMTP session.  If TLS negotiation
    fails (due to a certificate validation failure, for instance), the
    connection will be aborted.  This is better than `"never"`, but does not
    protect against an active adversary.

  * `"never"`: ignore whether the server advertises `STARTTLS`, and always use
    an unencrypted SMTP session.  This is a terrible idea, unless you are doing
    SMTP over a very trusted network.

  * `"smtps"`: don't use `STARTTLS` to negotiate TLS, but instead setup the
    TLS connection immediately and talk SMTP over that.  If your SMTP config
    includes port 465, or mentions "SMTPS", then this is *probably* the value
    you want.

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_TLS_VERIFY`** (default: `"yes"`) -- if you
  wish to live dangerously, you can turn off server certificate verification
  by setting this option to `"no"`.  However, if you're running a CA and you
  cannot figure out how to make your SMTP server present a valid certificate,
  you may wish to reconsider your life choices.


### Sendmail

```
ACMEVOKE_MAIL_DELIVERY_METHOD="sendmail"
```

Delivers mail by executing `/usr/sbin/sendmail` (or another path, if you
specify).  You don't have to be running the Sendmail MTA to use this method;
most MTAs provide a compatible `/usr/sbin/sendmail` program.

Available configuration environment variables:

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_SENDMAIL_PATH`** (default:
  `"/usr/sbin/sendmail"`) -- provide an alternate location for the `sendmail`
  binary for ACMEvoke to call when it sends mail.

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_SENDMAIL_OPTIONS`** (default: `"-i"`) --
  specify any command-line options that should be passed to `sendmail` when it
  is called.  If you don't know that you need this, then you really, *really*
  don't.


### File

```
ACMEVOKE_MAIL_DELIVERY_METHOD="file"
```

Doesn't actually "deliver" mail in any meaningful sense, but rather writes
the e-mails that are sent to a file, named for the recipient, in a stream.
It's not an mbox format, it's just a stream-of-RFC5322-consciousness.

Available configuration environment variables:

* **`ACMEVOKE_MAIL_DELIVERY_CONFIG_DIRECTORY`** (default: `"."`) -- the directory
  in which the file full of e-mail should be written.  The default is simply
  "whatever the current working directory is".


### Stderr

```
ACMEVOKE_MAIL_DELIVERY_METHOD="stderr"
```

Another "not really mail delivery" delivery method.  This one just dumps the
mails to `stderr`.  Since all other logs also get written to `stderr`, you'll
be doing well if this is useful to you in production.  Quite handy for local
testing, though.

There are no configuration environment variables for this delivery method.


# Contributing

Bug reports should be sent to the [Github issue
tracker](https://github.com/tobermorytech/acmevoke/issues).  Patches can be
sent as a [Github pull
request](https://github.com/tobermorytech/acmevoke/pulls).  This project is
intended to be a safe, welcoming space for collaboration, and contributors are
expected to adhere to the [Contributor Covenant code of
conduct](CODE_OF_CONDUCT.md).


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2020  Tobermory Technology Pty Ltd

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

