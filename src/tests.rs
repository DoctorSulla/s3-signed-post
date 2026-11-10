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

#[test]
fn test_signing() {
    let signing_key = derive_signing_key(
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "20151229",
        "us-east-1",
        "s3",
    );

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

    let x_amz_credential = "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request";

    let x_amz_date = "20261010T000000Z";

    let policy = Policy::new_with_exact_expiration(expiration, x_amz_credential, x_amz_date)
        .bucket("sample-bucket")
        .content_length_range(1000, 100000);

    let result = serde_json::to_string(&policy).unwrap();

    println!("{result}");

    let expected_result = format!(
        r#"{{"expiration":"{}","conditions":[{{"x-amz-credential":"{}"}},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-date":"{}"}},{{"bucket":"sample-bucket"}},["content-length-range",1000,100000]]}}"#,
        expiration, x_amz_credential, x_amz_date
    );

    assert_eq!(expected_result, result);
}

#[test]
fn test_starts_with_and_custom_conditions() {
    let expiration = Timestamp::now()
        .round(Unit::Millisecond)
        .unwrap()
        .checked_add(300.minutes())
        .unwrap();

    let x_amz_credential = "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request";
    let x_amz_date = "20261010T000000Z";

    let policy = Policy::new_with_exact_expiration(expiration, x_amz_credential, x_amz_date)
        .starts_with_key("user/user1/")
        .starts_with_content_type("image/")
        .condition(json!({"acl": "public-read"}));

    let result = serde_json::to_string(&policy).unwrap();

    let expected_result = format!(
        r#"{{"expiration":"{}","conditions":[{{"x-amz-credential":"{}"}},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-date":"{}"}},["starts-with","$key","user/user1/"],["starts-with","$content-type","image/"],{{"acl":"public-read"}}]}}"#,
        expiration, x_amz_credential, x_amz_date
    );

    assert_eq!(expected_result, result);
}
