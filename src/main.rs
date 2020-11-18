mod aws;
use aws::*;
use chrono::Utc;
use config::{Config, FileFormat};
use fastly::http::{HeaderMap, HeaderValue, Method, StatusCode};
use fastly::request::downstream_request;
use fastly::{Body, Error, Request, RequestExt, Response, ResponseExt};

/// The customers origin backend as defined in Tango
const CUSTOMER_ORIGIN: &str = "ShastaRain";
/// The nearline backend (e.g. wasabi, backblaze, etc) as defined in Tango.
const NEARLINE_BACKEND: &str = "backend_nlc";

/// Logging endpoint as defined in Tango.
const LOGGING_ENDPOINT: &str = "nearline_syslog";

const S3_DOMAIN: &str = "fsly-nlc-sfc.s3.us-west-002.backblazeb2.com";

/// The entry point for the application.
///
/// This function is triggered when the service receives a client request. This does not use the
/// main macro from the fastly crate because we want to do some processing after sending a
/// response back to the client.
///
fn main() -> Result<(), Error> {
    logging_init();


    let mut req = downstream_request();
    /*
    if req.headers().get("fastly-debug").unwrap == "true" {
        log::debug!("Fastly Debug On");
    }
    */

    // Save the method from the original request because we will need to to determine what should
    // be sent back to the client.
    let original_method = req.method().clone();
    if original_method == Method::GET || original_method == Method::HEAD {
        let url = req.uri().path().to_string();
        set_aws_headers(req.headers_mut(), url, Method::GET)?;
        let mut beresp = req.send(NEARLINE_BACKEND)?;
        log::debug!("Status from nearline: {:?}", beresp.status());

        if beresp.status() == StatusCode::FORBIDDEN || beresp.status() == StatusCode::NOT_FOUND {
            // This was a nearline cache MISS so build and send the request to the customer origin.
            let new_req = beresp.fastly_metadata().unwrap().sent_req().unwrap();
            beresp = Request::builder()
                .method(new_req.method())
                .uri(new_req.uri())
                .body(())
                .unwrap()
                .send(CUSTOMER_ORIGIN)?;

            if beresp.status() == StatusCode::OK {
                // Get the uri out of the request we sent to the origin.
                let uri = beresp
                    .fastly_metadata()
                    .unwrap()
                    .sent_req()
                    .unwrap()
                    .uri()
                    .clone();
                // Grab the path, we'll need it for the aws headers.
                let url_path = uri.path().to_string();
                let (parts, body) = beresp.into_parts();
                let chunks = body.into_bytes();
                let default_header_value = &HeaderValue::from_str("0").unwrap();
                let content_length = parts
                    .headers
                    .get("Content-Length")
                    .unwrap_or(default_header_value);
                let content_type = parts
                    .headers
                    .get("Content-Type")
                    .unwrap_or(default_header_value);

                // Send a copy of the response down to the client. If this was a GET return the
                // body otherwise it was a head so just leave the body empty.
                let mut client_body = Body::new();
                if original_method == Method::GET {
                    client_body = Body::from(chunks.as_slice());
                }
                Response::builder()
                    .body(client_body)?
                    .headers(parts.headers())
                    .send_downstream();

                // Build a new PUT request and send it to the nearline cache.
                log::debug!("URI: {:?} URL: {:?}", uri, url_path);
                let mut nearline_put_req = Request::builder()
                    .method(Method::PUT)
                    .uri(uri)
                    .header("Content-Length", content_length)
                    .header("Content-Type", content_type)
                    .body(Body::from(chunks.as_slice()))
                    .unwrap();

                set_aws_headers(nearline_put_req.headers_mut(), url_path, Method::PUT)?;
                let nlresp = nearline_put_req.send(NEARLINE_BACKEND)?;
                let status = nlresp.status();
                log::debug!("Response from NL Status: {:?}", status);
            } else {
                // The customer origin returned an error (non 200 status) so return the error to the
                // client
                beresp.send_downstream();
            }
        } else {
            // We got the object from nearline so return it to the client.
            beresp.send_downstream();
        }
    } else {
        // This was not a get or head so just send to customer origin and return response.
        req.send(CUSTOMER_ORIGIN)?.send_downstream();
    }
    Ok(())
    // Set timer for 20ish seconds and log it's taking a long time.
}

fn set_aws_headers(headers: &mut HeaderMap, url: String, method: Method) -> Result<(), Error> {
    headers.insert("Host", HeaderValue::from_static(S3_DOMAIN));
    let right_now = Utc::now();
    let auth_header = aws_v4_auth(
        "s3",
        S3_DOMAIN,
        "",
        method.as_str(),
        url.as_str(),
        right_now,
    );
    headers.insert("Authorization", auth_header.parse()?);

    let x_amz_date = right_now.format("%Y%m%dT%H%M%SZ").to_string();
    headers.insert("x-amz-date", x_amz_date.parse()?);
    if method == Method::GET {
        headers.insert("x-amz-content-sha256", empty_payload_hash().parse()?);
    } else if method == Method::PUT {
        headers.insert("x-amz-content-sha256", unsigned_payload_hash().parse()?);
    }
    Ok(())
}

/// This function reads the fastly.toml file and gets the deployed version. This is only run at
/// compile time. Since we bump the version number after building (during the deploy) we return
/// the version incremented by one so the version returned will match the deployed version.
fn get_version() -> i32 {
    Config::new()
        .merge(config::File::from_str(
            include_str!("../fastly.toml"), // assumes the existence of fastly.toml
            FileFormat::Toml,
        ))
        .unwrap()
        .get_str("version")
        .unwrap()
        .parse::<i32>()
        .unwrap_or(0)
        + 1
}

// Boiler plate function that I will include in every app until we have something in place that
// doe this.
fn logging_init() {
    log_fastly::Logger::builder()
        .max_level(log::LevelFilter::Debug)
        .default_endpoint(LOGGING_ENDPOINT)
        .init();

    fastly::log::set_panic_endpoint(LOGGING_ENDPOINT).unwrap();

    log::debug!("ECP Nearline Version:{}", get_version());
}
