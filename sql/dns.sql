-- DNS database
--

BEGIN;

-- Domains
-- This produces a zone file
CREATE TABLE domains (
	name		VARCHAR
			PRIMARY KEY,

-- Is this a reverse?
	reverse		BOOLEAN,

-- Default TTL for entries
	ttl		INTERVAL,

	refresh		INTERVAL,
	retry		INTERVAL,
	expire		INTERVAL,
	minimum		INTERVAL,

	contact		VARCHAR,

	serial		INTEGER,

	ns0		VARCHAR,

	ts		TIMESTAMP
			DEFAULT CURRENT_TIMESTAMP,

-- Timestamp of when serial number last changed
-- If this is less than ts then serial needs to be incremented
	updated		TIMESTAMP
);

-- Networks - Supplements the domains
CREATE TABLE networks (
	domain		VARCHAR
			PRIMARY KEY
			REFERENCES domains(name)
				ON DELETE CASCADE
				ON UPDATE CASCADE,

	network		CIDR
			UNIQUE
);

--CREATE FUNCTION trig_update_ts()
--	RETURNS TRIGGER
--	AS $$
--	BEGIN
--		NEW.updated=CURRENT_TIMESTAMP;
--		RETURN NEW;
--	END;
--	$$ LANGUAGE 'plpgsql';

-- Trigger function to update the 'updated' value when something changes
-- on another table
CREATE OR REPLACE FUNCTION trig_update_ts_before()
	RETURNS TRIGGER
	AS $$
	BEGIN
		UPDATE domains
			SET updated=CURRENT_TIMESTAMP
			WHERE name=OLD.domain;
		RETURN OLD;
	END;
	$$ LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION trig_update_ts_after()
	RETURNS TRIGGER
	AS $$
	BEGIN
		UPDATE domains
			SET updated=CURRENT_TIMESTAMP
			WHERE name=NEW.domain;
		RETURN NEW;
	END;
	$$ LANGUAGE 'plpgsql';

-- We also need two more triggers for the hosts table to change the entries
-- that corespond to networks. This is required in order to also update
-- the reverse.
CREATE OR REPLACE FUNCTION trig_update_ts_before_hosts()
	RETURNS TRIGGER
	AS $$
	BEGIN
		UPDATE domains
			SET updated=CURRENT_TIMESTAMP
			WHERE name=(
				SELECT domain
					FROM networks
					WHERE network>>OLD.ip
					ORDER BY masklen(network) DESC
					LIMIT 1
			);
		RETURN OLD;
	END;
	$$ LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION trig_update_ts_after_hosts()
	RETURNS TRIGGER
	AS $$
	BEGIN
		UPDATE domains
			SET updated=CURRENT_TIMESTAMP
			WHERE name=(
				SELECT domain
					FROM networks
					WHERE network>>NEW.ip
					ORDER BY masklen(network) DESC
					LIMIT 1
			);
		RETURN NEW;
	END;
	$$ LANGUAGE 'plpgsql';
------------------------------------------------------------------------------

-- NS records
CREATE TABLE ns (
	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE CASCADE
				ON UPDATE CASCADE,

--	hostname	VARCHAR,
--
	ns		VARCHAR
			NOT NULL,

	ttl		INTERVAL,

	PRIMARY KEY(domain, ns)
);


-- MX records
CREATE TABLE mx (
	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

	hostname	VARCHAR,

	priority	INTEGER,

	mx		VARCHAR,

	ttl		INTERVAL,

	PRIMARY KEY(domain, hostname, mx)

--	FOREIGN KEY(domain, hostname)
--		REFERENCES hostnames(domain, hostname)
--			ON DELETE CASCADE
--			ON UPDATE CASCADE
);

-- DS records
-- http://tools.ietf.org/html/rfc4034#section-5
-- http://tools.ietf.org/html/rfc4034#appendix-A.1
-- Entries can be stored in two places: Either for the full domain or
-- for the domain (as hostname) under the parent domain.
-- It is preferred to store it under the domain. In that case all
-- entries will have hostname set to NULL except from leaf entries
CREATE SEQUENCE seq_dnssec_id;
CREATE TABLE dnssec (
	id		INTEGER
			DEFAULT NEXTVAL('seq_dnssec_id')
			PRIMARY KEY,

	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

--	hostname	VARCHAR,

-- Auto-generated
	keyid		INTEGER
			NOT NULL,

-- Is this a KSK ?
	ksk		BOOLEAN,

-- Algorithm
-- http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
--	1: RSA/MD5 - bad
--	2: Diffie-Helman - not for signing
--	3: DSA/SHA-1
--	-4: Elliptic Curve - not available yet
--	5: RSA/SHA-1
--	8: RSASHA256
--	10: RSASHA512
	algorithm	INTEGER
			NOT NULL
			CHECK (algorithm IN (3,5,8,10)),

-- Digest type:
--	1: SHA-1
--	2: SHA-256
--	digesttype	INTEGER,

--	This is always 3
--	protocol	INTEGER
--			DEFAULT 3,

-- digest for DS record (for parent zone) (usually in case of KSK)
-- Auto-generated
	digest_sha1	VARCHAR,
	digest_sha256	VARCHAR,

-- public key for DNSKEY record (zone)
	key_pub		VARCHAR,

-- Full file contents of the public key file
	st_key_pub	VARCHAR,

-- Full contents of the private key file
	st_key_priv	VARCHAR,

-- Timestamps
	ts_created	TIMESTAMP,
	ts_activate	TIMESTAMP,
	ts_publish	TIMESTAMP,

	ttl		INTERVAL
);

CREATE INDEX idx_dnssec_main ON dnssec(domain, keyid);

-- TBD
--CREATE TABLE dnssec_private (
--	domain		VARCHAR
--			NOT NULL,
--
--	hostname	VARCHAR
--			NOT NULL,
--
--	PRIMARY KEY(domain, hostname),
--
--	FOREIGN KEY(domain, hostname)
--		REFERENCES dnssec(domain, hostname)
--			ON DELETE CASCADE
--			ON UPDATE CASCADE
--
--);

-- CNAMEs:
-- This produces:
--	hostname.domain IN CNAME hostname0
CREATE TABLE cnames (
	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

	hostname	VARCHAR
			NOT NULL,

	hostname0	VARCHAR
			NOT NULL,

	ttl		INTERVAL,

	PRIMARY KEY(domain, hostname)
);

-- TXTs:
CREATE TABLE txt (
	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

	hostname	VARCHAR
			NOT NULL,

	txt		VARCHAR
			NOT NULL,

	ttl		INTERVAL,

	PRIMARY KEY(domain, hostname, txt)
);

-- Dynamic IPs - to be read from existing files
CREATE TABLE dynamic (
	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

	hostname	VARCHAR
			NOT NULL,

	PRIMARY KEY(domain, hostname)
);

----------------------------------------------------------------------

-- Trigger to ensure that a network entry exists in the networks table
CREATE OR REPLACE FUNCTION func_trig_ip_check()
	RETURNS TRIGGER
	AS $$
	DECLARE
		rec	RECORD;
	BEGIN
		SELECT count(*) AS cnt
			INTO rec
			FROM networks
			WHERE NEW.ip << networks.network;

		IF rec.cnt = 0 THEN
			RAISE EXCEPTION 'No network found for % in networks', NEW.ip;
		END IF;

		RETURN NEW;
	END;
	$$ LANGUAGE 'plpgsql';

-- Set this as the reverse IP (i.e. the one that has reverse)
-- Only do that if no other exists
-- Also, if this is set to be true then make everything else false
CREATE OR REPLACE FUNCTION func_trig_hosts_set_reverse()
	RETURNS TRIGGER
	AS $$
	DECLARE
		rec	RECORD;
	BEGIN
		IF NEW.reverse THEN
			-- If the new entry is reverse then remove the
			-- reverse flag from all other entries
			-- Made in a way that works both for updates and
			-- inserts
			UPDATE hosts SET reverse='f'
				WHERE hosts.ip=NEW.ip AND
					reverse='t' AND
					(NEW.hostname<>hosts.hostname OR 
						NEW.domain<>hosts.domain);
		ELSEIF NEW.reverse IS NULL THEN
			-- If no value was provided then check
			-- If there is an existing reverse then set this as
			-- false, else set it as true
			SELECT count(*) AS cnt
				INTO rec
				FROM hosts
				WHERE NEW.ip=hosts.ip;

			IF rec.cnt = 0 THEN
				NEW.reverse='t';
			ELSE
				NEW.reverse='f';
			END IF;
		END IF;

		RETURN NEW;
	END;
	$$ LANGUAGE 'plpgsql';

-- Check that an address corepsonds to a host
-- Check whether the prefix is 32 for IPv4 or 128 for IPv6
CREATE OR REPLACE FUNCTION func_is_host(ip INET)
	RETURNS BOOLEAN
	AS $$
	BEGIN
		IF (family(ip)=4 AND masklen(ip)=32)
			OR (family(ip)=6 AND masklen(ip)=128) THEN
			RETURN TRUE;
		ELSE
			RETURN FALSE;
		END IF;
	END;
	$$ LANGUAGE 'plpgsql';

-- Simple ip to host mappings
CREATE TABLE hosts (
	ip		INET
			CHECK(func_is_host(ip)),

	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

	hostname	VARCHAR
			NOT NULL,

	reverse		BOOLEAN,

	ttl		INTERVAL,

	PRIMARY KEY(domain, hostname, ip)
);

CREATE TABLE dkim (
	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

	hostname	VARCHAR
			NOT NULL,

	selector	VARCHAR
			NOT NULL,

-- Key type:
-- - rsa
	k		VARCHAR
			NOT NULL,

	key_pub		VARCHAR
			NOT NULL,

-- Hashing Algorithm - May be NULL
-- - sha1
-- - sha256
	h		VARCHAR
			DEFAULT 'sha256',

-- granularity
	g		VARCHAR
			NOT NULL
			DEFAULT '*',

-- Testing?
	t		BOOLEAN
			NOT NULL
			DEFAULT FALSE,

-- Are subdomains allowed?
	subdomains	BOOLEAN
			NOT NULL
			DEFAULT FALSE,

	ttl		INTERVAL,

	PRIMARY KEY(domain, hostname, selector)
);

CREATE TABLE sshfp (
	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

	hostname	VARCHAR
			NOT NULL,

-- Key type:
-- 1: RSA
-- 2: DSA
	keytype		INTEGER
			NOT NULL,

-- Hash type:
-- 1: SHA-1
	hashtype	INTEGER
			NOT NULL,

-- Fingerprint
	fingerprint	VARCHAR
			NOT NULL,

	ttl		INTERVAL,

	PRIMARY KEY(domain, hostname, keytype, hashtype)
);

CREATE TYPE PROTOCOL AS ENUM('tcp', 'udp', 'sctp', 'dccp');

CREATE TABLE srv (
	domain		VARCHAR
			NOT NULL
			REFERENCES domains(name)
				ON DELETE RESTRICT
				ON UPDATE CASCADE,

	name		VARCHAR,

	protocol	PROTOCOL
			NOT NULL,

	service		VARCHAR
			NOT NULL,

	priority	INTEGER
			NOT NULL,

	weight		INTEGER
			NOT NULL,

	port		INTEGER
			NOT NULL,

	target		VARCHAR
			NOT NULL,

	ttl		INTERVAL,

	PRIMARY KEY(domain, name, protocol, service, priority, port, target)
);

-----------------------------------------------------------------------------
-- Triggers for updating the domains timestamp - a pair for each table

-- This one is causing problems: Each serial update also fires the trigger
-- which then causes another serial update, etc etc...
-- CREATE TRIGGER trig_domains_updated BEFORE INSERT OR UPDATE ON domains
-- 	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts();

CREATE TRIGGER trig_hosts_domain_ts_before BEFORE DELETE ON hosts
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_hosts_domain_ts_after AFTER INSERT OR UPDATE ON hosts
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();
-- hosts have the two additional triggers
CREATE TRIGGER trig_hosts_domain_ts_before_hosts BEFORE DELETE ON hosts
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before_hosts();
CREATE TRIGGER trig_hosts_domain_ts_after_hosts AFTER INSERT OR UPDATE ON hosts
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after_hosts();

CREATE TRIGGER trig_cnames_domain_ts_before BEFORE DELETE ON cnames
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_cnames_domain_ts_after AFTER INSERT OR UPDATE ON cnames
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

CREATE TRIGGER trig_dkim_domain_ts_before BEFORE DELETE ON dkim
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_dkim_domain_ts_after AFTER INSERT OR UPDATE ON dkim
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

CREATE TRIGGER trig_dnssec_domain_ts_before BEFORE DELETE ON dnssec
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_dnssec_domain_ts_after AFTER INSERT OR UPDATE ON dnssec
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

CREATE TRIGGER trig_mx_domain_ts_before BEFORE DELETE ON mx
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_mx_domain_ts_after AFTER INSERT OR UPDATE ON mx
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

CREATE TRIGGER trig_ns_domain_ts_before BEFORE DELETE ON ns
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_ns_domain_ts_after AFTER INSERT OR UPDATE ON ns
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

CREATE TRIGGER trig_txt_domain_ts_before BEFORE DELETE ON txt
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_txt_domain_ts_after AFTER INSERT OR UPDATE ON txt
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

CREATE TRIGGER trig_dynamic_domain_ts_before BEFORE DELETE ON dynamic
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_dynamic_domain_ts_after AFTER INSERT OR UPDATE ON dynamic
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

CREATE TRIGGER trig_sshfp_domain_ts_before BEFORE DELETE ON sshfp
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_sshfp_domain_ts_after AFTER INSERT OR UPDATE ON sshfp
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

CREATE TRIGGER trig_srv_domain_ts_before BEFORE DELETE ON srv
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_before();
CREATE TRIGGER trig_srv_domain_ts_after AFTER INSERT OR UPDATE ON srv
	FOR EACH ROW EXECUTE PROCEDURE trig_update_ts_after();

-- End of triggers for updating the domains timestamp
-----------------------------------------------------------------------------

CREATE INDEX idx_hosts_ip ON hosts(ip);

-- Bad idea since we may point to IPs that are not ours
--CREATE TRIGGER trig_hosts_ip
--	BEFORE UPDATE ON hosts
--	FOR EACH ROW EXECUTE PROCEDURE func_trig_ip_check();

CREATE TRIGGER trig_hosts_set_reverse
	AFTER INSERT OR UPDATE ON hosts
	FOR EACH ROW EXECUTE PROCEDURE func_trig_hosts_set_reverse();

--CREATE TRIGGER trig_ips_check
--	BEFORE UPDATE ON ips
--	FOR EACH ROW EXECUTE PROCEDURE func_trig_ips_check();

COMMIT;

