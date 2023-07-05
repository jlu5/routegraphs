-- All seen ASNs
CREATE TABLE "ASNs" (
  "asn" integer PRIMARY KEY,
  "direct_feed" integer default 0
);

-- All seen prefixes
CREATE TABLE "Prefixes" (
  "network" varchar,
  "length" integer,
  PRIMARY KEY("network", "length")
);

-- Prefix <-> origin ASN mapping
CREATE TABLE "PrefixOriginASNs" (
  "asn" integer,
  "prefix_network" varchar,
  "prefix_length" varchar,
  UNIQUE("asn", "prefix_network", "prefix_length"),
  FOREIGN KEY("prefix_network", "prefix_length") REFERENCES Prefixes("network", "length"),
  FOREIGN KEY("asn") REFERENCES ASNs("asn")
);

-- Prefix -> path mapping. One prefix can have multiple paths, and vice versa (deduplicating paths shared by multiple prefixes)
CREATE TABLE "PrefixPaths" (
  "network" varchar,
  "length" integer,
  "path_id" integer,
  UNIQUE("network", "length", "path_id"),
  FOREIGN KEY("network", "length") REFERENCES Prefixes("network", "length"),
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
