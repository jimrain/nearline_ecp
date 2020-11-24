mod aws;
use aws::*;
use chrono::Utc;
use std::time::{SystemTime, UNIX_EPOCH};
use config::{Config, FileFormat};
use fastly::http::{HeaderMap, HeaderValue, Method, StatusCode};
use fastly::request::downstream_request;
use fastly::{downstream_client_ip_addr, Body, Error, Request, RequestExt, Response, ResponseExt};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::io::Read;

/// The customers origin backend as defined in Tango
const CUSTOMER_ORIGIN: &str = "ShastaRain";
/// The nearline backend (e.g. wasabi, backblaze, etc) as defined in Tango.
const NEARLINE_BACKEND: &str = "backend_nlc";

/// Logging endpoint as defined in Tango.
const LOGGING_ENDPOINT: &str = "nearline_syslog";
const SUMO_LOGGING_ENDPOINT: &str = "sumo_log";
const S3_DOMAIN: &str = "fsly-nlc-sfc.s3.us-west-002.backblazeb2.com";

#[derive(Serialize, Deserialize, Debug)]
struct SumoLogEntry {
    time_start: u64,
    service_id: String,
    service_version: u32,
    client_ip: String,
    geo_city: String,
    geo_country_code: String,
    geo_continent_code: String,
    geo_region: String,
    request_user_agent: String,
    request_range: String,
    request_accept_content: String,
    request_accept_language: String,
    request_accept_encoding: String,
    request_accept_charset: String,
    request_connection: String,
    request_dnt: String,
    request_forwarded: String,
    request_via: String,
    request_cache_control: String,
    request_x_requested_with: String,
    request_x_forwarded_for: String,
    request: String,
    host: String,
    url: String,
    longitude: f64,
    latitude: f64,
    // Response headers must be options because I can't populate them when I instantiate the
    // struct.
    origin_host: String,
    status: String,
    content_type: String,
    response_age: String,
    response_cache_control: String,
    response_expires: String,
    response_last_modified: String,
    x_cache: String,
    response_content_length: String,
    /*
    req_header_size: Option<String>,,
    resp_header_size: Option<String>,
     */
}
/// The entry point for the application.
///
/// This function is triggered when the service receives a client request. This does not use the
/// main macro from the fastly crate because we want to do some processing after sending a
/// response back to the client.
///
fn main() -> Result<(), Error> {
    let mut req = downstream_request();
    let mut sumo_log_entry = logging_init(&req);

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

                set_sumo_log_entries(&beresp, &mut sumo_log_entry, false);
                set_response_headers(beresp.headers_mut(), false);
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
                    // .headers(parts.headers())
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
                set_sumo_log_entries(&beresp, &mut sumo_log_entry, false);
                set_response_headers(beresp.headers_mut(), false);
                beresp.send_downstream();
            }
        } else {
            // We got the object from nearline so return it to the client.
            sumo_log_entry.origin_host = format!("orig-{}", "orig_host");
            set_sumo_log_entries(&beresp, &mut sumo_log_entry, true);
            set_response_headers(beresp.headers_mut(), true);
            beresp.send_downstream();
        }
    } else {
        // This was not a get or head so just send to customer origin and return response.
        let mut beresp = req.send(CUSTOMER_ORIGIN)?;
        set_sumo_log_entries(&beresp, &mut sumo_log_entry, false);
        set_response_headers(beresp.headers_mut(), false);
        beresp.send_downstream();
    }

    let le = serde_json::to_string(&sumo_log_entry);
    log::info!(target: SUMO_LOGGING_ENDPOINT, "{}", le.unwrap());

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
fn get_version() -> u32 {
    Config::new()
        .merge(config::File::from_str(
            include_str!("../fastly.toml"), // assumes the existence of fastly.toml
            FileFormat::Toml,
        ))
        .unwrap()
        .get_str("version")
        .unwrap()
        .parse::<u32>()
        .unwrap_or(0)
        + 1
}

fn get_service_id() -> String {
    Config::new()
        .merge(config::File::from_str(
            include_str!("../fastly.toml"), // assumes the existence of fastly.toml
            FileFormat::Toml,
        ))
        .unwrap()
        .get_str("service_id")
        .unwrap()
}
// Boiler plate function that I will include in every app until we have something in place that
// doe this.
fn logging_init(req: &Request<Body>) -> SumoLogEntry {

    let headers = req.headers();

    if get_header_val_or_none(headers, "fastly-debug".to_string()) == "true" {
        // TODO: turn off syslog endpoint if this is off.
        log::debug!("Fastly Debug On");
    }

    log_fastly::Logger::builder()
        .max_level(log::LevelFilter::Debug)
        .default_endpoint(LOGGING_ENDPOINT)
        .endpoint(SUMO_LOGGING_ENDPOINT)
        .init();

    fastly::log::set_panic_endpoint(LOGGING_ENDPOINT).unwrap();

    let version = get_version();
    let client_ip = fastly::downstream_client_ip_addr().unwrap();
    let geo = fastly::geo::geo_lookup(client_ip).unwrap();
    log::debug!("ECP Nearline Version:{}", version);

    let sumo_log_entry = SumoLogEntry {
        time_start: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        service_version: version,
        client_ip: client_ip.to_string(),
        service_id: get_service_id(),
        geo_city: geo.city().to_string(),
        geo_country_code: geo.country_code().to_string(),
        geo_continent_code: geo.continent().as_code().to_string(),
        geo_region: geo.region().unwrap().to_string(),
        request_user_agent: get_header_val_or_none(headers, "user-agent".to_string()),
        request_range: get_header_val_or_none(headers, "range".to_string()),
        request_accept_content: get_header_val_or_none(headers, "accept".to_string()),
        request_accept_language: get_header_val_or_none(headers, "accept-language".to_string()),
        request_accept_encoding: get_header_val_or_none(headers, "accept-encoding".to_string()),
        request_accept_charset: get_header_val_or_none(headers, "accept-charset".to_string()),
        request_connection: get_header_val_or_none(headers, "connection".to_string()),
        request_dnt: get_header_val_or_none(headers, "dnt".to_string()),
        request_forwarded: get_header_val_or_none(headers, "forwarded".to_string()),
        request_via: get_header_val_or_none(headers, "via".to_string()),
        request_cache_control: get_header_val_or_none(headers, "cache-control".to_string()),
        request_x_requested_with: get_header_val_or_none(headers, "x-requested-with".to_string()),
        request_x_forwarded_for: get_header_val_or_none(headers, "x-forwarded-for".to_string()),
        host: get_header_val_or_none(headers, "host".to_string()),
        url: req.uri().path().to_string(),
        request: req.method().to_string(),
        longitude: geo.longitude(),
        latitude: geo.latitude(),
        // Set these to 0 for now and we will populate when we get a response.
        origin_host: "0".to_string(),
        status: "0".to_string(),
        content_type: "0".to_string(),
        response_age: "0".to_string(),
        response_cache_control: "0".to_string(),
        response_expires: "0".to_string(),
        response_last_modified: "0".to_string(),
        x_cache: "0".to_string(),
        response_content_length: 0.to_string(),
    };
    sumo_log_entry
}

fn set_sumo_log_entries(resp: &Response<Body>, sumo_log_entry: &mut SumoLogEntry, is_nlc: bool) {
    let orig_host = resp.fastly_metadata().unwrap().sent_req().unwrap().uri().host().unwrap().to_string();
    if is_nlc {
      sumo_log_entry.origin_host = format!("nlc-{}", orig_host);
    } else {
        sumo_log_entry.origin_host = format!("orig-{}", orig_host);
    }

    // resp.body().into_bytes().len();
    let headers = resp.headers();
    sumo_log_entry.status = resp.status().to_string();
    sumo_log_entry.content_type = get_header_val_or_none(headers, "content-type".to_string());
    sumo_log_entry.response_age = get_header_val_or_none(headers, "age".to_string());
    sumo_log_entry.response_cache_control = get_header_val_or_none(headers, "cache-control".to_string());
    sumo_log_entry.response_cache_control = get_header_val_or_none(headers, "cache-control".to_string());
    sumo_log_entry.response_expires = get_header_val_or_none(headers, "expires".to_string());
    sumo_log_entry.response_last_modified = get_header_val_or_none(headers, "last-modified".to_string());
    sumo_log_entry.x_cache = get_header_val_or_none(headers, "x-cache".to_string());
    sumo_log_entry.response_content_length = get_header_val_or_none(headers, "content-length".to_string());


}

fn set_response_headers(headers: &mut HeaderMap, is_nlc_cache_hit: bool) {
       if is_nlc_cache_hit {
        headers.append("x-nlc-cache", HeaderValue::from_static("HIT"));
    } else {
        headers.append("x-nlc-cache", HeaderValue::from_static("MISS"));
    }
}

fn get_header_val_or_none(headers: &HeaderMap, key: String) -> String {
    let default_header_value = &HeaderValue::from_str("0").unwrap();
    headers
        .get(key)
        .unwrap_or(default_header_value)
        .to_str()
        .unwrap_or_default()
        .to_string()
}
/*
{

  "req_header_size": "%{req.header_bytes_read}V",
  "req_body_size": "%{req.body_bytes_read}V",
  "resp_header_size": "%{resp.header_bytes_written}V",
  "resp_body_size": "%{resp.body_bytes_written}V"
}
 */
