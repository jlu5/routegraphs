-- All seen ASNs
CREATE TABLE "ASNs" (
  "asn" integer PRIMARY KEY,
  "direct_feed" integer default 0,
  "name" text
);

-- All seen prefixes
CREATE TABLE "Prefixes" (
  "network" varbinary(16),
  "length" integer,
  "broadcast_address" varbinary(16),
  PRIMARY KEY("network", "length")
);

-- All ROA records
CREATE TABLE "ROAEntries" (
  "network" varbinary(16),
  "length" integer, -- length of the prefix
  "broadcast_address" varbinary(16),
  "asn" integer,
  "max_length" integer, -- max length of more specifics
  PRIMARY KEY("network", "length", "asn")
);

-- Prefix <-> origin ASN mapping
CREATE TABLE "Announcements" (
  "asn" integer,
  "prefix_network" varbinary(16),
  "prefix_length" integer,
  UNIQUE("asn", "prefix_network", "prefix_length"),
  FOREIGN KEY("prefix_network", "prefix_length") REFERENCES Prefixes("network", "length"),
  FOREIGN KEY("asn") REFERENCES ASNs("asn")
);

-- Prefix -> path mapping. One prefix can have multiple paths, and vice versa (deduplicating paths shared by multiple prefixes)
CREATE TABLE "PrefixPaths" (
  "prefix_network" varbinary(16),
  "prefix_length" integer,
  "path_id" integer,
  UNIQUE("prefix_network", "prefix_length", "path_id"),
  FOREIGN KEY("prefix_network", "prefix_length") REFERENCES Prefixes("network", "length"),
  FOREIGN KEY("path_id") REFERENCES Paths("path_id")
);

-- Ordered list of ASes within a path
CREATE TABLE "Paths" (
  "path_id" integer,
  "list_index" integer,
  "asn" integer,
  UNIQUE("path_id", "list_index"),
  FOREIGN KEY("asn") REFERENCES ASNs("asn")
);

-- Track adjacencies seen in AS Paths.
-- A (receiver, sender) pair of (1, 2) means some AS path "... 1 2 ..." exists in the MRT dump
CREATE TABLE "NeighbourASNs" (
  "receiver_asn" integer,
  "sender_asn" integer,
  "transit" integer default 0,
  PRIMARY KEY("receiver_asn", "sender_asn"),
  FOREIGN KEY("receiver_asn") REFERENCES ASNs("asn"),
  FOREIGN KEY("sender_asn") REFERENCES ASNs("asn")
);

-- Like NeighbourASNs but bidirectional
CREATE VIEW NeighbourASNsBidi AS
SELECT receiver_asn AS local_asn, sender_asn AS peer_asn
FROM NeighbourASNs UNION
SELECT sender_asn AS local_asn, receiver_asn AS peer_asn
FROM NeighbourASNs;

-- Number of peers per ASN
CREATE VIEW ASNPeerCount AS
SELECT local_asn as asn, COUNT(peer_asn) AS n_peers
FROM NeighbourASNsBidi
GROUP BY asn;

-- All advertisements and whether they pass ROA / are a GRC leak
CREATE VIEW RouteAdvertisementROA AS
SELECT ann.prefix_network, ann.prefix_length, ann.asn, COUNT(roa.network) as roa_ok, (SELECT count(path_id) > 1 FROM PrefixPaths pp WHERE pp.prefix_network == ann.prefix_network AND pp.prefix_length == ann.prefix_length) as public
FROM Announcements ann
INNER JOIN Prefixes p -- to get access to broadcast_address
ON p.network = ann.prefix_network AND p.length = ann.prefix_length
LEFT JOIN ROAEntries roa
ON ann.asn = roa.asn AND ann.prefix_network >= roa.network AND ann.prefix_length <= roa.max_length AND roa.broadcast_address >= p.broadcast_address
GROUP BY ann.prefix_network, ann.prefix_length, ann.asn;
