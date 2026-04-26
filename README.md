# Threat Landscape API

> **Base URL:** `https://api.threatlandscape.io/rest/v1`

The Threat Landscape API delivers continuously updated, machine-readable cyber threat intelligence as **STIX 2.1 bundles**. Data is collected and enriched from both open-source intelligence (OSINT) and darknet sources, then normalized into structured records that can be queried, filtered, and integrated into any security platform.

---

## Contents

- [Authentication](#authentication)
- [Quick Start](#quick-start)
- [Endpoint Reference](#endpoint-reference)
  - [GET /stix\_bundles](#get-stix_bundles)
- [Field Reference](#field-reference)
- [Filtering](#filtering)
  - [Scalar filters](#scalar-filters)
  - [Array filters](#array-filters)
  - [Logical operators](#logical-operators)
- [Pagination](#pagination)
- [Sorting](#sorting)
- [Selecting specific columns](#selecting-specific-columns)
- [Common Query Recipes](#common-query-recipes)
- [STIX Bundle Structure](#stix-bundle-structure)

---

## Authentication

All requests require an API key. Include it in the `apikey` header:

```bash
-H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

Alternatively, send it as a Bearer token in the `Authorization` header:

```bash
-H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

API keys are issued per account. Keep your key secret — do not include it in client-side code, public repositories, or logs. Contact support to rotate a compromised key.

---

## Quick Start

Retrieve the 10 most recent threat bundles:

```bash
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=bundle_id,source_type,threat_actors,malware_names,created_at&order=created_at.desc&limit=10' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

---

## Endpoint Reference

### GET /stix\_bundles

Returns STIX 2.1 threat intelligence bundles. Each record represents one enriched bundle with denormalized filter columns for fast querying.

**URL**

```
GET https://api.threatlandscape.io/rest/v1/stix_bundles
```

**Query parameters**

| Parameter  | Description                                                        |
|------------|--------------------------------------------------------------------|
| `select`   | Comma-separated list of columns to return. Use `*` for all.       |
| `order`    | `column.asc` or `column.desc`                                     |
| `limit`    | Maximum number of rows to return (see [Pagination](#pagination))  |
| `offset`   | Row offset for pagination                                          |
| `Range`    | HTTP header for range-based pagination (e.g. `0-9`)               |

Filter parameters are applied as query string key/value pairs — see [Filtering](#filtering).

---

## Field Reference

| Field                   | Type                    | Description                                                                                          |
|-------------------------|-------------------------|------------------------------------------------------------------------------------------------------|
| `id`                    | `uuid`                  | Internal record identifier (auto-generated).                                                         |
| `bundle_id`             | `text`                  | STIX 2.1 bundle ID (e.g. `bundle--<uuid>`). Unique key; used for deduplication.                     |
| `source_type`           | `text`                  | `osint` — open-source / public feed, or `darknet` — darknet / underground source.                   |
| `created_at`            | `timestamptz`           | Timestamp when the record was ingested into the API.                                                 |
| `earliest_ts`           | `timestamptz`           | Earliest `created` timestamp of any STIX object inside the bundle.                                  |
| `latest_ts`             | `timestamptz`           | Latest `modified` timestamp of any STIX object inside the bundle.                                   |
| `stix_bundle`           | `jsonb`                 | Full STIX 2.1 bundle payload. Conforms to the [STIX 2.1 specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html). |
| `title`                 | `text`                  | Title of the threat report (from extraction or report name).                                        |
| `summary`               | `text`                  | Summary text of the threat report (from extraction or report description).                          |
| `threat_actors`         | `text[]`                | Names of `threat-actor` SDOs present in the bundle.                                                 |
| `malware_names`         | `text[]`                | Names of `malware` SDOs present in the bundle.                                                      |
| `campaigns`             | `text[]`                | Names of `campaign` SDOs present in the bundle.                                                     |
| `identities`            | `text[]`                | Names of `identity` SDOs present in the bundle.                                                     |
| `intrusion_sets`        | `text[]`                | Names of `intrusion-set` SDOs present in the bundle (e.g. APT groups).                              |
| `attack_patterns`       | `text[]`                | Names of `attack-pattern` SDOs (e.g. MITRE ATT&CK techniques).                                     |
| `vulnerabilities`       | `text[]`                | CVE IDs or vulnerability names from `vulnerability` SDOs.                                           |
| `locations`             | `text[]`                | Names of `location` SDOs present in the bundle.                                                     |
| `indicators_ipv4`       | `text[]`                | IPv4 addresses extracted from STIX `indicator` patterns.                                            |
| `indicators_ipv6`       | `text[]`                | IPv6 addresses extracted from STIX `indicator` patterns.                                            |
| `indicators_domain`     | `text[]`                | Domain names extracted from STIX `indicator` patterns.                                              |
| `indicators_url`        | `text[]`                | URLs extracted from STIX `indicator` patterns.                                                      |
| `indicators_hash_md5`   | `text[]`                | MD5 file hashes extracted from STIX `indicator` patterns.                                           |
| `indicators_hash_sha1`  | `text[]`                | SHA-1 file hashes extracted from STIX `indicator` patterns.                                         |
| `indicators_hash_sha256`| `text[]`                | SHA-256 file hashes extracted from STIX `indicator` patterns.                                       |
| `victims`               | `text[]`                | Victim organization or entity names.                                                                |
| `countries_target`      | `text[]`                | Countries identified as targets of the described threat activity.                                   |
| `countries_source`      | `text[]`                | Countries identified as the source / origin of the threat activity.                                 |
| `sectors`               | `text[]`                | Industry sectors targeted (e.g. `Finance`, `Healthcare`, `Government`).                             |
| `sectors_isic`          | `text[]`                | Sector codes using the [ISIC Rev.4](https://unstats.un.org/unsd/classifications/Econ/isic) taxonomy.|

---

## Filtering

The API uses [PostgREST](https://postgrest.org/en/stable/api.html#horizontal-filtering-rows) filter syntax. Filters are appended as query string parameters.

### Scalar filters

| Operator | Meaning                         | Example                                         |
|----------|---------------------------------|-------------------------------------------------|
| `eq`     | Equal to                        | `source_type=eq.darknet`                        |
| `neq`    | Not equal to                    | `source_type=neq.osint`                         |
| `gt`     | Greater than                    | `latest_ts=gt.2025-01-01T00:00:00Z`             |
| `gte`    | Greater than or equal to        | `latest_ts=gte.2025-01-01T00:00:00Z`            |
| `lt`     | Less than                       | `earliest_ts=lt.2024-01-01T00:00:00Z`           |
| `lte`    | Less than or equal to           | `earliest_ts=lte.2024-12-31T23:59:59Z`          |
| `like`   | Pattern match (case-sensitive)  | `bundle_id=like.bundle--*`                      |
| `ilike`  | Pattern match (case-insensitive)| `bundle_id=ilike.bundle--*`                     |
| `is`     | Is null / not null              | `threat_actors=is.null`                         |
| `in`     | In a set of values              | `source_type=in.(osint,darknet)`                |

```bash
# All darknet bundles
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=bundle_id,source_type,threat_actors&source_type=eq.darknet' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

```bash
# Bundles updated after 1 Jan 2025
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=bundle_id,latest_ts,malware_names&latest_ts=gte.2025-01-01T00:00:00Z' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

### Array filters

Use these operators to query the denormalized array columns (`threat_actors`, `malware_names`, `indicators_ipv4`, etc.).

| Operator | Meaning                           | Example                                                  |
|----------|-----------------------------------|----------------------------------------------------------|
| `cs`     | Array **contains** all elements   | `threat_actors=cs.{APT29}`                               |
| `cd`     | Array is **contained by** the set | `sectors=cd.{Finance,Banking,Insurance}`                 |

```bash
# Bundles mentioning APT29
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,threat_actors,malware_names,sectors" \
  -d "threat_actors=cs.{APT29}"
```

```bash
# Bundles containing a specific SHA-256 indicator
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,indicators_hash_sha256,stix_bundle" \
  -d "indicators_hash_sha256=cs.{e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}"
```

```bash
# Bundles targeting the Finance sector
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,sectors,threat_actors,countries_target" \
  -d "sectors=cs.{Finance}"
```

```bash
# Bundles with activity targeting United States
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,countries_target,threat_actors,vulnerabilities" \
  -d "countries_target=cs.{United States}"
```

### Logical operators

```bash
# OR: bundles from Greenland OR Iceland as source country
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,countries_source,threat_actors" \
  -d "or=(countries_source.cs.{Greenland},countries_source.cs.{Iceland})"
```

```bash
# NOT: exclude osint source type
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,source_type" \
  -d "source_type=not.eq.osint"
```

---

## Pagination

Use the `Range` header to page through results. The format is `start-end` (zero-indexed, both inclusive).

```bash
# First page (records 0–9)
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=bundle_id,created_at&order=created_at.desc' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -H "Range: 0-9"

# Second page (records 10–19)
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=bundle_id,created_at&order=created_at.desc' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -H "Range: 10-19"
```

Alternatively, use `limit` and `offset` query parameters:

```bash
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=bundle_id,created_at&order=created_at.desc&limit=10&offset=20' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

---

## Sorting

Append `order=<column>.<direction>` to any request. Direction is `asc` or `desc`.

```bash
# Most recently modified bundles first
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=bundle_id,latest_ts,source_type&order=latest_ts.desc' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

---

## Selecting specific columns

To reduce response payload, list only the columns you need with the `select` parameter:

```bash
# Return only IOC indicator fields
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=bundle_id,indicators_ipv4,indicators_ipv6,indicators_domain,indicators_url,indicators_hash_sha256' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

---

## Common Query Recipes

### All fields for a specific bundle

```bash
curl 'https://api.threatlandscape.io/rest/v1/stix_bundles?select=*&bundle_id=eq.bundle--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

### Threat actor pivot — all bundles mentioning Lazarus Group

```bash
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,threat_actors,malware_names,campaigns,countries_target,victims,latest_ts" \
  -d "threat_actors=cs.{Lazarus Group}" \
  -d "order=latest_ts.desc"
```

### Vulnerability intelligence — bundles referencing a CVE

```bash
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,vulnerabilities,threat_actors,attack_patterns,stix_bundle" \
  -d "vulnerabilities=cs.{CVE-2024-12345}"
```

### IOC lookup — check if an IP is present in any bundle

```bash
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,indicators_ipv4,threat_actors,latest_ts" \
  -d "indicators_ipv4=cs.{198.51.100.42}"
```

### Ransomware victim intelligence (darknet)

```bash
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,victims,threat_actors,sectors,countries_target,latest_ts" \
  -d "source_type=eq.darknet" \
  -d "order=latest_ts.desc" \
  -H "Range: 0-49"
```

### Sector-based threat report — Healthcare sector, last 30 days

```bash
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,sectors,threat_actors,malware_names,vulnerabilities,attack_patterns,countries_source,latest_ts" \
  -d "sectors=cs.{Healthcare}" \
  -d "latest_ts=gte.2026-03-17T00:00:00Z" \
  -d "order=latest_ts.desc"
```

### Country-targeted intelligence feed

```bash
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=bundle_id,countries_target,threat_actors,malware_names,sectors,latest_ts" \
  -d "or=(countries_target.cs.{Germany},countries_target.cs.{Austria},countries_target.cs.{Switzerland})" \
  -d "order=latest_ts.desc"
```

### Full STIX bundle download with IOC enrichment

```bash
curl --get 'https://api.threatlandscape.io/rest/v1/stix_bundles' \
  -H "apikey: YOUR_THREATLANDSCAPE_API_KEY" \
  -d "select=stix_bundle,indicators_ipv4,indicators_domain,indicators_hash_sha256" \
  -d "latest_ts=gte.2026-04-01T00:00:00Z" \
  -d "order=latest_ts.desc" \
  -H "Range: 0-99"
```

---

## STIX Bundle Structure

The `stix_bundle` field contains a full [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) bundle. Every bundle produced by the Threat Landscape platform includes a `report` object as its **primary context object** — it is always the first object in the `objects` array.

### The `report` object

The `report` SDO is the entry point for understanding a bundle. It contains:

| Field                | Description                                                                                      |
|----------------------|--------------------------------------------------------------------------------------------------|
| `name`               | Title of the threat report (e.g. `"Storm-2755 Payroll Piracy Uses AiTM and Token Replay"`).    |
| `description`        | Multi-sentence analyst summary of the threat activity.                                           |
| `published`          | ISO 8601 timestamp when the report was published.                                                |
| `labels`             | Always contains `"threat-landscape-report"`.                                                     |
| `report_types`       | Always contains `"threat-report"`.                                                               |
| `object_refs`        | List of STIX IDs of every other object in the bundle — use this to traverse the graph.           |
| `external_references`| Source URLs and CVE references that were used to generate the bundle.                            |
| `created_by_ref`     | References the `identity--` object for `threatlandscape.io`.                                     |

All other SDOs in the bundle (`threat-actor`, `campaign`, `indicator`, `relationship`, etc.) are linked via `object_refs` and connected to each other through `relationship` objects.

### SDO types present in bundles

| STIX Type          | Description                                                        |
|--------------------|--------------------------------------------------------------------|
| `threat-actor`     | Named threat actor group or individual                             |
| `malware`          | Malware family or specimen                                         |
| `campaign`         | Named offensive campaign                                           |
| `intrusion-set`    | Persistent threat group (e.g eCrime cluster)               |
| `attack-pattern`   | Technique or tactic (often mapped to MITRE ATT&CK)                |
| `vulnerability`    | Known vulnerability (CVE or otherwise)                             |
| `indicator`        | Observable-based pattern (IP, domain, hash, URL)                  |
| `identity`         | Organization, sector, or system identity                           |
| `location`         | Geographic location object                                         |
| `relationship`     | Directed link between two SDOs                                     |
| `report`           | Primary context object — title, description, source URLs, and refs to all other objects |
| `bundle`           | Top-level container                                                |

### Example bundle

The following is a real bundle returned by the API. The `report` object appears first and references all other objects via `object_refs`.

```json
{
  "id": "bundle--185f682b-486a-42e5-9860-203be3a1052f",
  "type": "bundle",
  "objects": [
    {
      "id": "report--3b6020a6-153f-4684-b25b-c5fe7381a903",
      "lang": "en",
      "name": "Storm-2755 Payroll Piracy Uses AiTM and Token Replay",
      "type": "report",
      "labels": ["threat-landscape-report"],
      "created": "2026-04-09T19:09:39.993767Z",
      "revoked": false,
      "modified": "2026-04-09T19:09:39.993767Z",
      "published": "2026-04-09T19:09:39.993767Z",
      "description": "Microsoft observed Storm-2755 conducting financially motivated payroll piracy against Canadian users by hijacking authenticated cloud sessions and redirecting salary payments to attacker-controlled accounts.\n- Initial access used malvertising and SEO poisoning to lead victims to a fake Microsoft 365 sign-in page and capture credentials and session tokens.\n- The actor used adversary-in-the-middle techniques, token replay, and Axios-based session persistence to bypass non-phishing-resistant MFA and maintain access.\n- Post-compromise activity focused on discovering payroll and HR workflows, creating inbox rules to hide bank/direct-deposit correspondence, and impersonating employees to alter payment details in SaaS platforms such as Workday.\n- The campaign caused direct financial loss and demonstrates the value of phishing-resistant MFA, rapid token revocation, and inbox-rule monitoring.",
      "object_refs": [
        "location--fc9b7f35-41a2-4899-859e-e60627612204",
        "identity--767a1659-fdb1-495c-8d47-3837f058e93b",
        "identity--3ee65bd6-4b3e-4c52-b950-e9bbccf1818f",
        "threat-actor--9400cbac-7438-4957-b626-1e32c49a1d06",
        "campaign--2cf40a02-25cd-4e0e-a313-e5d6b63801ed",
        "vulnerability--89fca13c-48e4-4890-bb99-625345caa108",
        "indicator--24f6ebf2-9917-4976-867c-d13ae03ad992",
        "indicator--d7f78d01-c6b2-45ea-9d6a-fad44bc80bf7",
        "relationship--c3ae0e81-05bd-4549-9f37-228d2024d670",
        "relationship--f073a291-e043-4074-9128-36a028d620ef"
      ],
      "report_types": ["threat-report"],
      "spec_version": "2.1",
      "created_by_ref": "identity--2f63f8e1-a880-4e9f-89e6-bd86c1d5939e",
      "external_references": [
        {
          "url": "https://www.microsoft.com/en-us/security/blog/2026/04/09/investigating-storm-2755-payroll-pirate-attacks-targeting-canadian-employees/",
          "source_name": "microsoft.com"
        },
        {
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-27152",
          "external_id": "CVE-2025-27152",
          "source_name": "cve"
        }
      ]
    },
    {
      "id": "location--fc9b7f35-41a2-4899-859e-e60627612204",
      "name": "Canada",
      "type": "location",
      "country": "CA",
      "created": "2026-04-09T19:05:03.759937Z",
      "modified": "2026-04-09T19:05:03.759937Z",
      "spec_version": "2.1"
    },
    {
      "id": "identity--767a1659-fdb1-495c-8d47-3837f058e93b",
      "name": "Human resources",
      "type": "identity",
      "created": "2026-04-09T19:05:03.760029Z",
      "modified": "2026-04-09T19:05:03.760029Z",
      "spec_version": "2.1"
    },
    {
      "id": "threat-actor--9400cbac-7438-4957-b626-1e32c49a1d06",
      "name": "Storm-2755",
      "type": "threat-actor",
      "created": "2026-04-09T19:05:03.760101Z",
      "modified": "2026-04-09T19:05:03.760101Z",
      "spec_version": "2.1"
    },
    {
      "id": "campaign--2cf40a02-25cd-4e0e-a313-e5d6b63801ed",
      "name": "Payroll pirate attacks targeting Canadian users",
      "type": "campaign",
      "created": "2026-04-09T19:05:03.760112Z",
      "modified": "2026-04-09T19:05:03.760112Z",
      "spec_version": "2.1"
    },
    {
      "id": "vulnerability--89fca13c-48e4-4890-bb99-625345caa108",
      "name": "CVE-2025-27152",
      "type": "vulnerability",
      "created": "2026-04-09T19:05:03.760125Z",
      "modified": "2026-04-09T19:05:03.760125Z",
      "spec_version": "2.1",
      "external_references": [
        {
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-27152",
          "external_id": "CVE-2025-27152",
          "source_name": "cve"
        }
      ]
    },
    {
      "id": "indicator--24f6ebf2-9917-4976-867c-d13ae03ad992",
      "name": "Domain-name indicator",
      "type": "indicator",
      "created": "2026-04-09T19:05:03.760265Z",
      "pattern": "[domain-name:value = 'bluegraintours.com']",
      "modified": "2026-04-09T19:05:03.760265Z",
      "valid_from": "2026-04-09T19:05:03.760265Z",
      "description": "Domain-name indicator",
      "pattern_type": "stix",
      "spec_version": "2.1",
      "pattern_version": "2.1"
    },
    {
      "id": "indicator--d7f78d01-c6b2-45ea-9d6a-fad44bc80bf7",
      "name": "URL indicator",
      "type": "indicator",
      "created": "2026-04-09T19:05:03.760265Z",
      "pattern": "[url:value = 'http://bluegraintours.com']",
      "modified": "2026-04-09T19:05:03.760265Z",
      "valid_from": "2026-04-09T19:05:03.760265Z",
      "description": "URL indicator",
      "pattern_type": "stix",
      "spec_version": "2.1",
      "pattern_version": "2.1"
    },
    {
      "id": "relationship--c3ae0e81-05bd-4549-9f37-228d2024d670",
      "type": "relationship",
      "created": "2026-04-09T19:09:38.229213Z",
      "modified": "2026-04-09T19:09:38.229213Z",
      "source_ref": "campaign--2cf40a02-25cd-4e0e-a313-e5d6b63801ed",
      "target_ref": "threat-actor--9400cbac-7438-4957-b626-1e32c49a1d06",
      "spec_version": "2.1",
      "relationship_type": "attributed-to"
    },
    {
      "id": "relationship--f073a291-e043-4074-9128-36a028d620ef",
      "type": "relationship",
      "created": "2026-04-09T19:09:38.229213Z",
      "modified": "2026-04-09T19:09:38.229213Z",
      "source_ref": "campaign--2cf40a02-25cd-4e0e-a313-e5d6b63801ed",
      "target_ref": "identity--c43727d4-dbce-4da1-94c2-674381292f88",
      "spec_version": "2.1",
      "relationship_type": "targets"
    },
    {
      "id": "identity--2f63f8e1-a880-4e9f-89e6-bd86c1d5939e",
      "name": "threatlandscape.io",
      "type": "identity",
      "created": "2025-06-23T12:00:00.000Z",
      "modified": "2025-06-23T12:00:00.000Z",
      "description": "Created by threatlandscape.io",
      "spec_version": "2.1",
      "identity_class": "organization"
    }
  ]
}
```

> **Note:** The full bundle stored in `stix_bundle` contains all objects listed in the `report.object_refs` array. The abbreviated example above omits some `relationship` objects for brevity.

---

*© Threat Landscape — threatlandscape.io. All rights reserved.*
