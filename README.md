# Summary
vdns is a DNS management tool with a database backend.
It uses the postgresql database and has some cool features.

The main job of vdns is to generate zone files based on the data of
the database. Other than that it is a library for handling DNS zone files
as it can read them.

More specifically, vdns is a modular tool that supports multiple inputs.
Currently it supports:

 * Reading zone data from a database
 * Reading zone data from a zone file

This makes vdns able to work well even when you are using Dynamic DNS to
update zone files as it can parse those files.

Most of the functionality of vdns is based around its library, which can
be used by other tools. The library supports reading zone files, generating
forward zone files and generating reverse zone files.

vdns is written in Python and should work with both python2 and python3
(if not, please file a bug report).

vdns supports the following:
 * IPv4 and IPv6
 * Forward and reverse records (A, AAAA and PTR)
 * MX, NS, CNAME, TXT, SSHFP and SRV records
 * DKIM
 * DNSSEC (DS and DNSKEY)
 * Automatic NS glue records for sub-zones
 * Human-readable serial numbers

The vdns database is a human-usable database and data are generated based
on that. I.e. the database is not a storage for raw DNS data. For example,
forward and reverse records are generated from the same set of data,
TXT records are generated from both TXT and DKIM data, etc.

# Installation
## Prerequisites
You will need:

 * A postgresql database
 * Python
 * psycopg2 python library

## Create the database

First create the postgresql database and grant access to it. E.g:

```
sudo -u postgres -i
createuser -P dns
createdb dns -E UNICODE -O dns
exit
```

The sql/ directory holds a .sql file that will create the database.
Use that to create the schema:

`psql -f sql/dns.sql dns -U dns`

Connect to the database and have a look at the schema:

```
psql -U dns dns

dns=> \dt
             List of relations
 Schema │     Name      │   Type   │ Owner 
────────┼───────────────┼──────────┼───────
 public │ cnames        │ table    │ dns
 public │ dkim          │ table    │ dns
 public │ dnssec        │ table    │ dns
 public │ domains       │ table    │ dns
 public │ dynamic       │ table    │ dns
 public │ hosts         │ table    │ dns
 public │ mx            │ table    │ dns
 public │ networks      │ table    │ dns
 public │ ns            │ table    │ dns
 public │ srv           │ table    │ dns
 public │ sshfp         │ table    │ dns
 public │ txt           │ table    │ dns
(13 rows)
```

# Usage
## Database

vdns uses PostgreSQL and takes advantage of its types. I.e don't expect
the hacks that one would need if they were using MySQL.

What you need to know:

 * Domains are strings, formatted just like in bind. Example names:
   * example.com
   * 10.in-addr.arpa
   * 8.4.3.0.1.0.a.2.ip6.arpa
 * Intervals use the [PostgreSQL Interval type](http://www.postgresql.org/docs/9.3/static/datatype-datetime.html#DATATYPE-INTERVAL-INPUT). Example values:
   * 1 day
   * 00:05:00
 * Booleans can be defined as 't' or 'f' for true/false
 * Timestamps use the [PostgreSQL Timestamp type](http://www.postgresql.org/docs/9.3/static/datatype-datetime.html#DATATYPE-DATETIME-INPUT)
   and will normally use the ISO format. Example:
   * 2015-09-27 16:09:53.926174
 * IP addresses use the [PostgreSQL INET type](http://www.postgresql.org/docs/9.3/static/datatype-net-types.html#DATATYPE-INET)
   which supports both IPv4 and IPv6. You can use this to query data
   in a more humane way than when using strings and to do other stuff
   like properly sorting the results. The format is the plain IPv4 or IPv6
   address. For example, you can fetch all entries with an IP tha belongs
   to the 10.1.0.0/16 network, properly sorter with:
   `SELECT * FROM hosts WHERE ip << '10.1.0.0/16' ORDER BY ip`
 * Networks use the [PostgreSQL CIDR type](http://www.postgresql.org/docs/9.3/static/datatype-net-types.html#DATATYPE-CIDR)
   which is similar to the INET type but also holds a subnet mask. Example:
   * 10.0.0.0/8
   * 2a01:348::/32

### Domains
The very first step is to define domains and networks. After that
you insert records to the relevant tables.

#### domains
You need one domain entry for each zone you have. You must list all
forward and reverse zones in the domains table. The fields are
as follows:

 * name: The name of the domain (string)
 * reverse: Whether this is a reverse zone (boolean)
 * ttl: as in SOA (interval)
 * refresh: as in SOA (interval)
 * retry: as in SOA (interval)
 * expire: as in SOA (interval)
 * minimum: as in SOA (interval)
 * contact: as in SOA (interval)
 * serial: as in SOA (integer)
 * ns0: as in SOA (string)
 * ts: The time this zone was last re-generated. This is handled by the
   vdns scripts. Leave it alone. (timestamp)
 * updated: Timestamp of the last time this zone had a change. This is handled by
   triggers. You should not have to touch this normally. Update it to the
   current timestamp if you want to force a zone regeneration. (timestamp)

Example:
```
INSERT INTO domains VALUES(
  'example.com', 'f', '1 day', '24:00:00', '01:00:00', '3 months',
  '01:00:00', 'example.example.com', '2016010900', 'ns1.example.com',
  NULL, NULL);
INSERT INTO domains VALUES(
  '10.in-addr.arpa', 't', '1 day', '24:00:00', '01:00:00', '3 months',
  '01:00:00', 'example.example.com', '2016010900', 'ns1.example.com',
  NULL, NULL);
```

#### networks
You need to define the networks for which you will generate reverse records.
More precisely, you need to associate domains to actual IP networks.

Example:
`INSERT INTO networks VALUES('10.in-addr.arpa', '10.0.0.0/8');`

### dynamic
If you are doing dynamic DNS updates then you need to specify the dynamic
entries per domain. This way vdns will know to load them from the old zone
files. For each dynamic host you need an entry in the dynamic table.

The dynamic table's fields are:

 * domain: The domain name
 * hostname: The hostname part

### Records

#### hosts
Host entries are the ip<->hostname mappings and they are stored in the hosts
table. The fields are:

 * ip: The IP address (IPv4 or IPv6)
 * domain: The domain this is relevant to. Only forward domains should be used
   here
 * hostname: The hostname part
 * reverse: A boolean to indicate that this entry will be used for a reverse
   record. For example, if two hostname are associated to the same IP address
   then only one of them will be used for the reverse entry (asusming that
   reverse entries will be generated). Only one record per IP address may have
   this flag set as true. There is a trigger that will flip the rest to false
   whenever one is set to true.
 * ttl: The TTL of the entry, or NULL to use the zone's default

Example:
```
INSERT INTO hosts VALUES('10.1.1.1', 'example.com', 'gw', 't');
INSERT INTO hosts VALUES('10.1.1.1', 'example.com', 'router', 'f');
INSERT INTO hosts VALUES('2001:1111:2222:3333::1', 'example.com', 'gw', 't');
```

#### cnames
CNAME entries:

 * domain: The domain this is relevant to
 * hostname: The hostname part
 * hostname0: The hostname to point to
 * ttl: Same as in hosts

Example:
`INSERT INTO cnames VALUES('example.com', 'mail', 'mail.google.com');`

#### dkim
DKIM data:

 * domain: The domain name
 * hostname: The hostname
 * selector: The DKIM selector
 * k: The key type. E.g. rsa
 * key_pub: The public key as a one-line string, without the
   BEGIN and END lines
 * h: The hashing algorithm, as in DKIM spec
 * g: Granularity, as in DKIM spec
 * t: Testing (boolean), whether to set the testing flag
 * subdomains (boolean), whether to set the subdomains flag
 * ttl: Same as in hosts

#### dnssec
DNSSEC data. These data are better handled in an automated way.

Note: The tool to import them is not yet in this repo.

Note: The dnssec data must be generated with an external tool and then
imported to vdns' database. Generating DNSSEC data is out of the scope of
vdns as the external tools will most probably be more reliable from a
security point of view.

The fields are as follows:

 * id: an auto-incremented number used as an ID. Leave the database to
   determine this number as it comes from a sequence.
 * domain: The domain name
 * keyid: The key-id
 * ksk: Whether this is a KSK (boolean)
 * algorithm: The algorithm id (e.g. 8)
 * digest_sha1: The sha1 digest
 * digest_sha256: The sha256 digest
 * key_pub: The public key
 * st_key_pub: The contents of the public key file, as generated by BIND's
   tools.
 * st_key_priv: The contents of the private key file, as generated by BIND's
   tools
 * ts_created: The Created time from within the public key file
 * ts_activate: The Activate time from within the public key file
 * ts_publish: The Publish time from within the public key file
 * ttl: Same as in hosts

Overall, all data in this table are just extracted data from st_key_pub
and st_key_priv.

#### mx
MX records:

 * domain: The domain name
 * hostname: The hostname part
 * priority: The MX priority
 * mx: The MX entry
 * ttl: Same as in hosts

#### ns
NS records:

 * domain: The domain name
 * ns: The NS record for the domain
 * ttl: Same as in hosts

Data from this table will be used both for zone NS records and for glue records.

#### srv
SRV records:

 * domain: The domain name
 * name: The SRV name (can be NULL)
 * protocol: The protocel (e.g. tcp), without a leading underscore
 * service: The service name (e.g. xmpp-client), without a leading underscore
 * priority: The priority of the target host (per SRV spec)
 * weight: The weight of the record (per SRV spec)
 * port: The port number
 * target: The SRV target
 * ttl: Same as in hosts
 
For example, this:
```
INSERT INTO srv VALUES(
  'example.com', 'test', 'tcp', 'xmpp-client', 5, 0, 5222, 'jabber');
```
will generate this record:

`_xmpp-client._tcp.test  IN      SRV     5 0 5222 jabber`

#### sshfp
SSHFP records:

 * domain: The domain name
 * hostname: The hostname part
 * keytype: The key type ID. 1: RSA, 2: DSA
 * hashtype: The hashing algorithm (fingerprint) id. 1: SHA-1
 * fingerprint: The fingerprint
 * ttl: Same as in hosts

Example:
```
INSERT INTO sshfp VALUES( 'example.com', 'srv', 1, 1,
  'abcdabcdabcdabcdabcd12312312312312312312');
```

#### txt
TXT records. Note that additional TXT records may be generated by data from
other tables if needed (e.g. DKIM)

 * domain: The domain name
 * hostname: The hostname part
 * txt: The TXT contents
 * ttl: Same as in hosts

vdns will break TXT data as needed

## Command line tool
### export
To generate the zone files you need to use the vdns script's export command.

Use `vdns --export` to see the accepted parameters.

For example, to generate the zone files for the things that were created
above:
```
mkdir /tmp/new

vdns.py export \
  --dbname dns \
  --dbuser dns \
  --outdir /tmp/new \
  --all
```

If you want to export a subset of zone or reverse zones then use the
`--domains` and `--networks` parameters instead of `--all`.

Example output:
```
-rw-r--r-- 1 v13 v13 311 Jan 10 00:20 10.in-addr.arpa
-rw-r--r-- 1 v13 v13 468 Jan 10 00:20 example.com

$ cat 10.in-addr.arpa
$ORIGIN         10.in-addr.arpa.
$TTL            1D      ; 1 day
@               1D      IN      SOA     ns1.example.com. example.example.com. (
                                2016011000      ; serial
                                1D              ; refresh (1 day)
                                1H              ; retry (1 hour)
                                90D             ; expire (12 weeks, 6 days)
                                1H              ; minimum (1 hour)
                                )


1.1.1                   IN      PTR     gw.example.com.

$ cat example.com
$ORIGIN         example.com.
$TTL            1D      ; 1 day
@               1D      IN      SOA     ns1.example.com. example.example.com. (
                                2016011001      ; serial
                                1D              ; refresh (1 day)
                                1H              ; retry (1 hour)
                                90D             ; expire (12 weeks, 6 days)
                                1H              ; minimum (1 hour)
                                )

_xmpp-client._tcp.test  IN      SRV     5 0 5222 jabber

gw                      IN      A       10.1.1.1
router                  IN      A       10.1.1.1
gw                      IN      AAAA    2001:1111:2222:3333::1

mail                    IN      CNAME   mail.google.com.
```
nice and easy

# Authors
Stefanos Harhalakis <v13@v13.gr>

# License
This project is developed and distributed under the Apache 2.0 license.

