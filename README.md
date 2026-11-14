# s3-signed-post

A simple library with an ergonomic API for facilitating signed browser-based POST uploads to Amazon S3 (and S3-compatible object stores).

## Quick Start

```rust
use jiff::Timestamp;
use s3_signed_post::{Policy, Region, Service, SigningContext};

let ctx = SigningContext::new(
    Region::UsEast1,
    Timestamp::now(),
    Service::S3,
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
);

let policy = Policy::new_with_expiration_in_minutes(15, &ctx)
    .bucket("my-bucket")
    .starts_with_key("uploads/user-1/")
    .content_length_range(1, 10 * 1024 * 1024)
    .starts_with_content_type("image/");

let fields = policy.get_post_fields(&ctx);
// `fields` contains `x-amz-credential`, `x-amz-algorithm`, `x-amz-date`,
// `key`, `policy`, and `x-amz-signature` ready to include in an HTML form
// or multipart/form-data POST request.
```

## Overview

- **`Policy`** — Builds an S3 POST policy as described in the [AWS SigV4 POST policy documentation](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-HTTPPOSTConstructPolicy.html). Uses a builder pattern for common conditions (`bucket`, `key`, `content_type`, `content_length_range`) with a `condition` method for custom fields, plus `sign` and `get_post_fields` helpers.
- **`SigningContext`** — Holds the region, timestamp, service, access key, secret key, and optional STS session token (`with_session_token`) used when building and signing policies.
- **`Region` / `Service`** — Enums for AWS regions and services, each with a `Custom(String)` variant for new regions or S3-compatible providers.
- **`derive_signing_key` / `get_policy_signature`** — Low-level functions for SigV4 key derivation and signing a policy JSON string directly.
