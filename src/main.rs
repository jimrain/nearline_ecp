use config::{Config, FileFormat};
use fastly::http::{HeaderValue, Method, StatusCode};
use fastly::request::CacheOverride;
use fastly::{Body, Error, Request, RequestExt, Response, ResponseExt};

/// The name of a backend server associated with this service.
///
/// This should be changed to match the name of your own backend. See the the `Hosts` section of
/// the Fastly WASM service UI for more information.
const CUSTOMER_ORIGIN: &str = "ShastaRain";

/// The name of a second backend associated with this service.
const NEARLINE_BACKEND: &str = "ShastaRain";

const LOGGING_ENDPOINT: &str = "nearline_syslog";

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
/// If `main` returns an error, a 500 error response will be delivered to the client.
#[fastly::main]
fn main(mut req: Request<Body>) -> Result<impl ResponseExt, Error> {
    logging_init();

    log::debug!("URI: {:?}", req.uri());
    let mut beresp = req.send(NEARLINE_BACKEND)?;

    if beresp.status() == StatusCode::FORBIDDEN {
        let mut new_req = beresp.fastly_metadata().unwrap().sent_req().unwrap();
        beresp = Request::builder()
            .method(new_req.method())
            .uri(new_req.uri())
            .body(())
            .unwrap()
            .send(CUSTOMER_ORIGIN)?;

        if beresp.status() == StatusCode::OK {
            let b = beresp.fastly_metadata().unwrap().sent_req().unwrap().uri().into_parts();
            Request::builder()
                .method(Method::PUT)
                // .uri(new_req.uri())
                .body(())
                .unwrap()
                .send_async(NEARLINE_BACKEND)?;
        }
    }

    Ok(beresp)
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
