mod aws;
use aws::*;
use chrono::DateTime;
use chrono::Utc;
use config::{Config, FileFormat};
use fastly::http::{HeaderMap, HeaderValue, Method, StatusCode};
use fastly::request::{CacheOverride, downstream_request};
use fastly::{Body, Error, Request, RequestExt, Response, ResponseExt};

/// The name of a backend server associated with this service.
///
/// This should be changed to match the name of your own backend. See the the `Hosts` section of
/// the Fastly WASM service UI for more information.
const CUSTOMER_ORIGIN: &str = "ShastaRain";

/// The name of a second backend associated with this service.
const NEARLINE_BACKEND: &str = "backend_nlc";

const LOGGING_ENDPOINT: &str = "nearline_syslog";

const S3_DOMAIN: &str = "fsly-nlc-sfc.s3.us-west-002.backblazeb2.com";

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
fn main() -> Result<(), Error> {
    logging_init();

    // log::debug!("URI: {:?}", req.uri());

    // JMR - Only do this for a GET and HEAD
    // JMR - Deal with HEAD (e.g. warm nearline cache). We have to issue a GET to s3 but when
    // we return to the client we don't send the body.

    let mut req = downstream_request();
    let url = req.uri().path().to_string();
    set_aws_headers(req.headers_mut(), url, Method::GET)?;
    let mut beresp = req.send(NEARLINE_BACKEND)?;
    log::debug!("Status from nearline: {:?}", beresp.status());

    if beresp.status() == StatusCode::FORBIDDEN || beresp.status() == StatusCode::NOT_FOUND {
        let mut new_req = beresp.fastly_metadata().unwrap().sent_req().unwrap();
        beresp = Request::builder()
            .method(new_req.method())
            .uri(new_req.uri())
            .body(())
            .unwrap()
            .send(CUSTOMER_ORIGIN)?;
        // We got a response from the origin so send it to the browser before we send it to
        // nearline.

        // beresp.send_downstream();


        if beresp.status() == StatusCode::OK {
            let uri = beresp.fastly_metadata().unwrap().sent_req().unwrap().uri().clone();
            let url = uri.path().to_string();
            let (parts, body) = beresp.into_parts();
            let chunks = body.into_bytes();

            let mut nearline_put_req = Request::builder()
                .method(Method::PUT)
                .uri(uri)
                .body(Body::from(chunks.as_slice()))
                .unwrap();

            set_aws_headers(nearline_put_req.headers_mut(), url, Method::PUT)?;
            let nlresp = nearline_put_req.send(NEARLINE_BACKEND)?;
            log::debug!("Response from NL Put: {:?}", nlresp.status());

            Response::builder()
                .body(Body::from(chunks.as_slice()))?
                .send_downstream();

            // beresp.body_mut().write_bytes(&chunks);
            // beresp.send_downstream();
        }


    } else {
        // We got the object from nearline so return it to the browser.
        beresp.send_downstream();
    }

    // JMR - If this is a head I need to remove body
    Ok(())
    // JMR - Loose macro and select and log success/failure.
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
