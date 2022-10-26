use std::collections::HashMap;

use axum::{
    body::Body,
    Extension,
    extract::OriginalUri,
    http::{header, request::Parts, Request, StatusCode, Uri},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::{SignedCookieJar, Cookie, Key};
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha1::Sha1;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let key = Key::generate();

    let app = Router::new()
        .route("/", get(index))
        .route("/lti", post(lti))
        .layer(Extension(key))
        .layer(TraceLayer::new_for_http());

    let app_path = std::env::var("APP_PATH").unwrap_or("/".into());
    let app = if app_path == "/" {
        app
    }
    else {
        Router::new().nest(&app_path, app)
    };

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn index(jar: SignedCookieJar) -> Result<(SignedCookieJar, String), StatusCode> {
    match (jar.get("name"), jar.get("count")) {
        (Some(name), Some(count)) => {
            let name = name.value().to_owned();
            let count = count.value().parse::<usize>().unwrap();
            let jar = jar
                .add(Cookie::new("count", format!("{}", count + 1)));
            let body = format!("Hello, {}.  You visited this page {} times.", name, count + 1);
            Ok((
                jar,
                body,
            ))
        },
        _ => {
            Err(StatusCode::UNAUTHORIZED)
        },
    }
}

async fn lti(jar: SignedCookieJar, OriginalUri(original_uri): OriginalUri, req: Request<Body>) -> Result<(SignedCookieJar, String), StatusCode> {
    let (parts, body) = req.into_parts();
    let body = String::from_utf8(hyper::body::to_bytes(body).await.unwrap().into()).unwrap();
    tracing::debug!("{:?}", parts);
    let opt_params = verify(original_uri, parts, body);
    tracing::debug!("{:?}", opt_params);
    match opt_params {
        Some(params) => {
            let params = params.into_iter().collect::<HashMap<_, _>>();
            let jar = jar
                .add(Cookie::new("name", params["lis_person_name_full"].to_owned()))
                .add(Cookie::new("count", "0"));
            let body = format!("{:?}", jar);
            Ok((
                jar,
                body,
            ))
        },
        None => {
            Err(StatusCode::UNAUTHORIZED)
        },
    }
}

fn verify(original_uri: Uri, parts: Parts, body: String) -> Option<Vec<(String, String)>> {
    // Characters not in the unreserved character set defined in https://www.rfc-editor.org/rfc/rfc5849#section-3.6
    const NON_UNRESERVED_CHARACTER_SET: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

    // Method
    let method = parts.method.as_str();
    tracing::debug!("{:?}", method);
    // URL
    let url = Uri::builder()
        .scheme(parts.headers.get("X-Forwarded-Proto").map(|v| v.to_str().unwrap()).unwrap_or("http"))
        .authority(parts.headers[header::HOST].to_str().unwrap())
        .path_and_query(original_uri.into_parts().path_and_query.unwrap())
        .build()
        .unwrap()
        .to_string();
    tracing::debug!("{:?}", url);
    // Params
    let mut kvs: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes()).into_owned().collect();
    kvs.sort();
    let params = kvs
        .iter()
        .filter(|(key, _)| {
            key != "oauth_signature"
        })
        .map(|(key, value)| {
            let encoded_key = utf8_percent_encode(&key, NON_UNRESERVED_CHARACTER_SET);
            let encoded_value = utf8_percent_encode(&value, NON_UNRESERVED_CHARACTER_SET);
            format!("{}={}", encoded_key, encoded_value)
        })
        .collect::<Vec<_>>()
        .join("&");
    tracing::debug!("{:?}", kvs);
    tracing::debug!("{:?}", params);
    // Base string
    let base_str = format!("{}&{}&{}",
        utf8_percent_encode(method, NON_UNRESERVED_CHARACTER_SET),
        utf8_percent_encode(&url, NON_UNRESERVED_CHARACTER_SET),
        utf8_percent_encode(&params, NON_UNRESERVED_CHARACTER_SET),
    );
    tracing::debug!("{:?}", base_str);
    // Signature key
    let signature_key = format!("{}&{}", "this_is_a_secret", "");
    tracing::debug!("{:?}", signature_key);
    // Find the code from a given signature
    let i = kvs.binary_search_by_key(&"oauth_signature", |(k, _)| k.as_str()).unwrap();
    let given_signature = kvs[i].1.as_str();
    let given_code = base64::decode(given_signature).unwrap();
    // Verify HMAC-SHA1 code
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(signature_key.as_bytes()).unwrap();
    mac.update(base_str.as_bytes());
    match mac.verify_slice(&given_code[..]) {
        Ok(_) => Some(kvs),
        _ => None,
    }
}
