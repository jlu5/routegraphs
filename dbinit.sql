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
CREATE TABLE "PrefixOriginASNs" (
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
