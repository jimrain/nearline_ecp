use chrono::DateTime;
use chrono::Utc;
use hmac_sha256::{Hash, HMAC};

const AWS_SERVICE: &str = "s3";
const AWS_REGION: &str = "us-west-002";
//const AWS_DOMAIN: &str = "fastlytest.s3.eu-central-1.wasabisys.com";
// https://s3.us-west-002.backblazeb2.com
const AWS_ACCESS_KEY_ID: &str = "0023a2cf5728b1f0000000001";
const AWS_SECRET_ACCESS_KEY: &str = "K002LBFTgqPJAKeQ2mlJKtwZ+bwYGDA";

// For uploads, we use the unsigned payload option.  To sign the payload
// we would need to read the body and hash it which we dont want to do.  We
// want to keep the body bytes out of the guest to avoid memory utilization.
// See:  https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
// The spec says that we put the literal string UNSIGNED-PAYLOAD in the payload
// instead of hex-encoded hash value
pub fn unsigned_payload_hash() -> String {
    "UNSIGNED-PAYLOAD".to_string()
}

pub fn empty_payload_hash() -> String {
    // hex::encode(HMAC::mac("".as_bytes(), &key))
    // HEX(SHA256("")) = below
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
}

// SHA256 HMAC
fn sign(key: Vec<u8>, input: String) -> [u8; 32] {
    HMAC::mac(input.as_bytes(), &key)
}

// Create a hex output of the hash
pub fn hash(input: String) -> String {
    hex::encode(Hash::hash(input.as_bytes()))
}

pub fn aws_v4_auth(
    service: &str,
    aws_domain: &str,
    payload: &str,
    method: &str,
    path: &str,
    now: DateTime<Utc>,
) -> String {
    let amz_content_256 = match method {
        "GET" | "HEAD" | "DELETE" => hash(payload.to_string()),
        _ => unsigned_payload_hash(),
    };

    let x_amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let x_amz_today = now.format("%Y%m%d").to_string();

    // The spec says we should urlencode everything but the `/`
    let encoded_path: String = urlencoding::encode(path);
    let final_encoded_path = encoded_path.replace("%2F", "/");

    // These must be sorted alphabetically
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        aws_domain, amz_content_256, x_amz_date
    );

    let canonical_query = "";

    // These must be alphabetic
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        final_encoded_path,
        canonical_query,
        canonical_headers,
        signed_headers,
        amz_content_256
    );

    let scope = format!("{}/{}/{}/aws4_request", x_amz_today, AWS_REGION, service);

    let signed_canonical_request = hash(canonical_request);

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        x_amz_date, scope, signed_canonical_request
    );

    // Generate the signature through the multi-step signing process
    let k_secret = format!("AWS4{}", &AWS_SECRET_ACCESS_KEY);
    let k_date = sign(k_secret.as_bytes().to_vec(), x_amz_today);
    let k_region = sign(k_date.to_vec(), AWS_REGION.to_string());
    let k_service = sign(k_region.to_vec(), AWS_SERVICE.to_string());
    let k_signing = sign(k_service.to_vec(), "aws4_request".to_string());

    // Final signature
    let signature = hex::encode(sign(k_signing.to_vec(), string_to_sign));

    // Generate the Authorization header value
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        AWS_ACCESS_KEY_ID, scope, signed_headers, signature
    )
}
