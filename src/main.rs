use std::collections::HashMap;

use axum::{
    body::Body,
    Extension,
    extract::OriginalUri,
    http::{header, Method, Request, StatusCode, Uri},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::{SignedCookieJar, Cookie, Key};
use hmac::{Hmac, Mac, digest::MacError};
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

    // Method
    let method = parts.method;
    tracing::debug!("{:?}", method);

    // URL
    let url = Uri::builder()
        .scheme(parts.headers.get("X-Forwarded-Proto").map(|v| v.to_str().unwrap()).unwrap_or("http"))
        .authority(parts.headers[header::HOST].to_str().unwrap())
        .path_and_query(original_uri.into_parts().path_and_query.unwrap())
        .build()
        .unwrap();
    tracing::debug!("{:?}", url);

    // Params
    let mut params: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes()).into_owned().collect();
    params.sort();
    tracing::debug!("{:?}", params);

    // Verify the signature
    let i = params.binary_search_by_key(&"oauth_signature", |(k, _)| k.as_str()).unwrap();
    let signature = params[i].1.as_str();
    let opt_params = match verify_signature(method, url, &params, "this_is_a_secret", signature) {
        Ok(_) => Some(params),
        _ => None,
    };
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

fn verify_signature(
    method: Method,
    url: Uri,
    params: &[(String, String)],
    consumer_secret: &str,
    signature: &str,
) -> Result<(), MacError> {
    // Characters not in the unreserved character set defined in https://www.rfc-editor.org/rfc/rfc5849#section-3.6
    const NON_UNRESERVED_CHARACTER_SET: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

    // Secret key
    let mut secret_key = String::from(consumer_secret);
    secret_key.push('&');

    // Initialize a Mac instance
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret_key.as_bytes()).unwrap();

    // Base string
    let params_string = params
        .iter()
        .filter(|(key, _)| key != "oauth_signature")
        .map(|(key, value)| {
            let mut result = utf8_percent_encode(&key, NON_UNRESERVED_CHARACTER_SET).to_string();
            result.push('=');
            utf8_percent_encode(&value, NON_UNRESERVED_CHARACTER_SET).for_each(|s| { result.push_str(s); });
            result
        })
        .collect::<Vec<_>>()
        .join("&");
    mac.update(method.as_str().as_bytes());
    mac.update(&[b'&']);
    utf8_percent_encode(url.to_string().as_str(), NON_UNRESERVED_CHARACTER_SET).for_each(|s| { mac.update(s.as_bytes()); });
    mac.update(&[b'&']);
    utf8_percent_encode(params_string.as_str(), NON_UNRESERVED_CHARACTER_SET).for_each(|s| { mac.update(s.as_bytes()); });

    // Verify HMAC-SHA1 code
    mac.verify_slice(&base64::decode(signature).unwrap())
}
