const EXAMPLE_POLICY: &str = r#"{ "expiration": "2015-12-30T12:00:00.000Z",
  "conditions": [
    {"bucket": "sigv4examplebucket"},
    ["starts-with", "$key", "user/user1/"],
    {"acl": "public-read"},
    {"success_action_redirect": "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html"},
    ["starts-with", "$Content-Type", "image/"],
    {"x-amz-meta-uuid": "14365123651274"},
    {"x-amz-server-side-encryption": "AES256"},
    ["starts-with", "$x-amz-meta-tag", ""],

    {"x-amz-credential": "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"},
    {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
    {"x-amz-date": "20151229T000000Z" }
  ]
}"#;

use super::*;
use jiff::{Timestamp, ToSpan, Unit};
use serde_json::json;

#[test]
fn test_signing() {
    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2015-12-29T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );

    let signing_key = derive_signing_key(&signing_context);

    let signed_policy = get_policy_signature(&EXAMPLE_POLICY.replace("\n", "\r\n"), &signing_key);

    assert_eq!(
        signed_policy.signature,
        "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"
    );

    assert_eq!(
        signed_policy.base64_encoding,
        "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9"
    );
}

#[test]
fn test_policy_generation() {
    let expiration = Timestamp::now()
        .round(Unit::Millisecond)
        .unwrap()
        .checked_add(300.minutes())
        .unwrap();

    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2026-10-10T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "",
    );

    let policy = Policy::new_with_exact_expiration(expiration, &signing_context)
        .bucket("sample-bucket")
        .content_length_range(1000, 100000);

    let result = serde_json::to_string(&policy).unwrap();

    println!("{result}");

    let expected_result = format!(
        r#"{{"expiration":"{}","conditions":[{{"x-amz-credential":"{}"}},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-date":"{}"}},{{"x-amz-server-side-encryption":"AES256"}},{{"bucket":"sample-bucket"}},["content-length-range",1000,100000]]}}"#,
        expiration,
        signing_context.get_credential(),
        signing_context.get_x_amz_date()
    );

    assert_eq!(expected_result, result);
}

#[test]
fn test_x_amz_date_format() {
    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2015-12-29T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "",
    );

    assert_eq!(signing_context.get_x_amz_date(), "20151229T000000Z");
}

#[test]
fn test_signing_context_masks_secret() {
    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2015-12-29T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );

    let result = serde_json::to_string(&signing_context).unwrap();

    assert!(result.contains(r#""secret_access_key":"**MASKED**""#));
    assert!(!result.contains("wJalrXUtnFEMI"));
}

#[test]
fn test_get_post_fields() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();

    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2015-12-29T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );

    let policy = Policy::new_with_exact_expiration(expiration, &signing_context)
        .bucket("sample-bucket")
        .starts_with_key("user/user1/");

    let fields = policy.get_post_fields(&signing_context);

    let signed = policy.sign(&derive_signing_key(&signing_context));

    assert_eq!(
        fields.get("key").map(String::as_str),
        Some("user/user1/${filename}")
    );
    assert_eq!(fields.get("policy"), Some(&signed.base64_encoding));
    assert_eq!(fields.get("x-amz-signature"), Some(&signed.signature));
    assert_eq!(
        fields.get("x-amz-algorithm").map(String::as_str),
        Some("AWS4-HMAC-SHA256")
    );
    assert_eq!(
        fields.get("x-amz-credential"),
        Some(&signing_context.get_credential())
    );
    assert_eq!(
        fields.get("x-amz-date").map(String::as_str),
        Some("20151229T000000Z")
    );
    assert!(!fields.contains_key("file"));
}

#[test]
fn test_get_post_fields_exact_key() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();

    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2015-12-29T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );

    let policy = Policy::new_with_exact_expiration(expiration, &signing_context)
        .bucket("sample-bucket")
        .key("user/user1/photo.jpg");

    let fields = policy.get_post_fields(&signing_context);

    assert_eq!(
        fields.get("key").map(String::as_str),
        Some("user/user1/photo.jpg")
    );
}

#[test]
fn test_starts_with_and_custom_conditions() {
    let expiration = Timestamp::now()
        .round(Unit::Millisecond)
        .unwrap()
        .checked_add(300.minutes())
        .unwrap();

    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2026-10-10T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "",
    );

    let policy = Policy::new_with_exact_expiration(expiration, &signing_context)
        .starts_with_key("user/user1/")
        .starts_with_content_type("image/")
        .condition(json!({"acl": "public-read"}));

    let result = serde_json::to_string(&policy).unwrap();

    let expected_result = format!(
        r#"{{"expiration":"{}","conditions":[{{"x-amz-credential":"{}"}},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-date":"{}"}},{{"x-amz-server-side-encryption":"AES256"}},["starts-with","$key","user/user1/"],["starts-with","$content-type","image/"],{{"acl":"public-read"}}]}}"#,
        expiration,
        signing_context.get_credential(),
        signing_context.get_x_amz_date()
    );

    assert_eq!(expected_result, result);
}

fn temporary_credentials_context() -> SigningContext {
    SigningContext::new(
        Region::UsEast1,
        "2015-12-29T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "ASIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    .with_session_token("FQoGZXIvYXdzEXAMPLETOKEN")
}

#[test]
fn test_session_token_in_conditions_and_fields() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = temporary_credentials_context();

    let policy = Policy::new_with_exact_expiration(expiration, &signing_context);

    let policy_json = serde_json::to_value(&policy).unwrap();
    assert!(
        policy_json["conditions"]
            .as_array()
            .unwrap()
            .contains(&json!({"x-amz-security-token": "FQoGZXIvYXdzEXAMPLETOKEN"}))
    );

    let fields = policy.get_post_fields(&signing_context);
    assert_eq!(
        fields.get("x-amz-security-token").map(String::as_str),
        Some("FQoGZXIvYXdzEXAMPLETOKEN")
    );
}

#[test]
fn test_no_session_token_by_default() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2015-12-29T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );

    let policy = Policy::new_with_exact_expiration(expiration, &signing_context);

    assert!(
        !serde_json::to_string(&policy)
            .unwrap()
            .contains("x-amz-security-token")
    );
    assert!(
        !policy
            .get_post_fields(&signing_context)
            .contains_key("x-amz-security-token")
    );
}

#[test]
fn test_session_token_is_masked() {
    let signing_context = temporary_credentials_context();

    let serialized = serde_json::to_string(&signing_context).unwrap();
    let debugged = format!("{signing_context:?}");

    for output in [serialized, debugged] {
        assert!(!output.contains("FQoGZXIvYXdzEXAMPLETOKEN"));
        assert!(output.contains("**MASKED**"));
    }
}

#[test]
fn test_exact_content_type_sets_field() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = temporary_credentials_context();

    let fields = Policy::new_with_exact_expiration(expiration, &signing_context)
        .content_type("image/png")
        .get_post_fields(&signing_context);

    assert_eq!(
        fields.get("Content-Type").map(String::as_str),
        Some("image/png")
    );
}

#[test]
fn test_starts_with_content_type_leaves_field_to_client() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = temporary_credentials_context();

    let fields = Policy::new_with_exact_expiration(expiration, &signing_context)
        .starts_with_content_type("image/")
        .get_post_fields(&signing_context);

    assert!(!fields.contains_key("Content-Type"));
}

fn policy_conditions(policy: &Policy) -> Vec<serde_json::Value> {
    serde_json::to_value(policy).unwrap()["conditions"]
        .as_array()
        .unwrap()
        .clone()
}

fn count_conditions_on(conditions: &[serde_json::Value], field: &str) -> usize {
    let dollar_field = format!("${field}");
    conditions
        .iter()
        .filter(|c| {
            c.get(field).is_some()
                || c.get(1).and_then(|v| v.as_str()) == Some(dollar_field.as_str())
        })
        .count()
}

#[test]
fn test_key_setters_replace_previous_key() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = temporary_credentials_context();

    let policy = Policy::new_with_exact_expiration(expiration, &signing_context)
        .starts_with_key("user/user1/")
        .key("user/user1/photo.jpg");

    let conditions = policy_conditions(&policy);
    assert_eq!(count_conditions_on(&conditions, "key"), 1);
    assert!(conditions.contains(&json!({"key": "user/user1/photo.jpg"})));
    assert_eq!(
        policy
            .get_post_fields(&signing_context)
            .get("key")
            .map(String::as_str),
        Some("user/user1/photo.jpg")
    );

    let policy = policy.starts_with_key("user/user2/");
    let conditions = policy_conditions(&policy);
    assert_eq!(count_conditions_on(&conditions, "key"), 1);
    assert!(conditions.contains(&json!(["starts-with", "$key", "user/user2/"])));
    assert_eq!(
        policy
            .get_post_fields(&signing_context)
            .get("key")
            .map(String::as_str),
        Some("user/user2/${filename}")
    );
}

#[test]
fn test_content_type_setters_replace_previous_content_type() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = temporary_credentials_context();

    // Exact then prefix: the Content-Type form field must be dropped too
    let policy = Policy::new_with_exact_expiration(expiration, &signing_context)
        .content_type("image/png")
        .starts_with_content_type("image/");

    let conditions = policy_conditions(&policy);
    assert_eq!(count_conditions_on(&conditions, "content-type"), 1);
    assert!(
        !policy
            .get_post_fields(&signing_context)
            .contains_key("Content-Type")
    );
}

#[test]
fn test_bucket_and_length_range_replace_previous() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = temporary_credentials_context();

    let policy = Policy::new_with_exact_expiration(expiration, &signing_context)
        .bucket("first")
        .bucket("second")
        .content_length_range(1, 10)
        .content_length_range(5, 50);

    let conditions = policy_conditions(&policy);
    assert_eq!(count_conditions_on(&conditions, "bucket"), 1);
    assert!(conditions.contains(&json!({"bucket": "second"})));
    let ranges: Vec<_> = conditions
        .iter()
        .filter(|c| c.get(0).and_then(|v| v.as_str()) == Some("content-length-range"))
        .collect();
    assert_eq!(ranges, vec![&json!(["content-length-range", 5, 50])]);
}

#[test]
fn test_conditions_have_fixed_order() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = SigningContext::new(
        Region::UsEast1,
        "2015-12-29T00:00:00Z".parse::<Timestamp>().unwrap(),
        Service::S3,
        "AKIAIOSFODNN7EXAMPLE",
        "",
    );

    // Setters called in reverse of the serialized order
    let policy = Policy::new_with_exact_expiration(expiration, &signing_context)
        .condition(json!({"acl": "public-read"}))
        .content_length_range(1, 10)
        .content_type("image/png")
        .key("a.png")
        .bucket("b");

    assert_eq!(
        policy_conditions(&policy),
        vec![
            json!({"x-amz-credential": signing_context.get_credential()}),
            json!({"x-amz-algorithm": "AWS4-HMAC-SHA256"}),
            json!({"x-amz-date": "20151229T000000Z"}),
            json!({"x-amz-server-side-encryption": "AES256"}),
            json!({"bucket": "b"}),
            json!({"key": "a.png"}),
            json!({"content-type": "image/png"}),
            json!(["content-length-range", 1, 10]),
            json!({"acl": "public-read"}),
        ]
    );
}

#[test]
fn test_get_s3_upload_url() {
    let expiration = "2015-12-30T12:00:00Z".parse::<Timestamp>().unwrap();
    let signing_context = temporary_credentials_context();

    let policy_without_bucket = Policy::new_with_exact_expiration(expiration, &signing_context);
    assert_eq!(policy_without_bucket.get_s3_upload_url(&signing_context), None);

    let policy_with_bucket = policy_without_bucket.bucket("sample-bucket");
    assert_eq!(
        policy_with_bucket.get_s3_upload_url(&signing_context),
        Some("https://sample-bucket.s3.us-east-1.amazonaws.com/".to_string())
    );
}
