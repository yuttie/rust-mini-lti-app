use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    body::Body,
    Extension,
    extract::{OriginalUri, Query},
    http::{header, Method, Request, StatusCode, Uri},
    response::Redirect,
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::{SignedCookieJar, Cookie, Key};
use hmac::{Hmac, Mac, digest::MacError};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation, errors::Error as JwtError};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// LTI 1.3 Data Structures
#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    iss: String,
    login_hint: String,
    target_link_uri: String,
    client_id: Option<String>,
    lti_deployment_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Lti13Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    nonce: String,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/message_type")]
    message_type: String,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/version")]
    version: String,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/deployment_id")]
    deployment_id: String,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/target_link_uri")]
    target_link_uri: String,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/resource_link")]
    resource_link: Option<ResourceLink>,
    #[serde(flatten)]
    other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResourceLink {
    id: String,
    description: Option<String>,
    title: Option<String>,
}

// Simple in-memory key store for demo purposes
// In production, this would be loaded from configuration or a database

type UsedNonceValues = Arc<Mutex<HashMap<String, Instant>>>;
type Lti13UsedNonceValues = Arc<Mutex<HashMap<String, Instant>>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let key = Key::generate();

    let used_nonce_values: UsedNonceValues = Arc::new(Mutex::new(HashMap::new()));
    let lti13_used_nonce_values: Lti13UsedNonceValues = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route("/", get(index))
        .route("/lti", post(lti))  // LTI 1.0/1.1 endpoint
        .route("/lti13/login", get(lti13_login))  // LTI 1.3 OIDC login initiation
        .route("/lti13/launch", post(lti13_launch))  // LTI 1.3 launch endpoint
        .layer(Extension(key))
        .layer(Extension(used_nonce_values))
        .layer(Extension(lti13_used_nonce_values))
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

async fn lti(
    jar: SignedCookieJar,
    OriginalUri(original_uri): OriginalUri,
    Extension(used_nonce_values): Extension<UsedNonceValues>,
    req: Request<Body>,
) -> Result<(SignedCookieJar, String), StatusCode> {
    let (parts, body) = req.into_parts();
    let body = hyper::body::to_bytes(body).await.unwrap();

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
    let mut params: Vec<(String, String)> = form_urlencoded::parse(&body).into_owned().collect();
    params.sort();
    tracing::debug!("{:?}", params);

    // Check nonce value
    let i = params.binary_search_by_key(&"oauth_nonce", |(k, _)| k.as_str()).unwrap();
    let nonce = params[i].1.as_str();
    {
        let mut used_nonce_values = used_nonce_values.lock().unwrap();
        used_nonce_values.retain(|_, time| time.elapsed().as_secs() <= 90 * 60);
        match used_nonce_values.get(nonce) {
            None => {
                used_nonce_values.insert(nonce.to_owned(), Instant::now());
            },
            Some(_) => {
                // Nonce value was reused
                return Err(StatusCode::BAD_REQUEST);
            },
        }
    }

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

// LTI 1.3 OIDC Login Initiation
async fn lti13_login(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Redirect, StatusCode> {
    tracing::debug!("LTI 1.3 login initiation: {:?}", params);

    // Extract required parameters
    let iss = params.get("iss").ok_or(StatusCode::BAD_REQUEST)?;
    let login_hint = params.get("login_hint").ok_or(StatusCode::BAD_REQUEST)?;
    let target_link_uri = params.get("target_link_uri").ok_or(StatusCode::BAD_REQUEST)?;
    let client_id = params.get("client_id");
    let _lti_deployment_id = params.get("lti_deployment_id");

    // Generate a nonce and state for OIDC flow
    let nonce = format!("nonce_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    let state = format!("state_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());

    // Build OIDC authentication request
    let mut auth_url = format!("{}/auth?", iss);
    let auth_params = [
        ("response_type", "id_token"),
        ("client_id", client_id.map_or("rust-mini-lti-app", |v| v)),
        ("redirect_uri", &format!("{}/lti13/launch", target_link_uri.split("/lti13/launch").next().unwrap_or("http://localhost:3000"))),
        ("login_hint", login_hint),
        ("state", &state),
        ("response_mode", "form_post"),
        ("nonce", &nonce),
        ("prompt", "none"),
    ];

    let query_string = auth_params
        .iter()
        .map(|(k, v)| format!("{}={}", k, percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)))
        .collect::<Vec<_>>()
        .join("&");

    auth_url.push_str(&query_string);

    tracing::info!("Redirecting to: {}", auth_url);
    Ok(Redirect::to(&auth_url))
}

// LTI 1.3 Launch Handler
async fn lti13_launch(
    jar: SignedCookieJar,
    Extension(lti13_used_nonce_values): Extension<Lti13UsedNonceValues>,
    req: Request<Body>,
) -> Result<(SignedCookieJar, String), StatusCode> {
    let (_parts, body) = req.into_parts();
    let body = hyper::body::to_bytes(body).await.unwrap();

    // Parse form data
    let params: HashMap<String, String> = form_urlencoded::parse(&body)
        .into_owned()
        .collect();

    tracing::debug!("LTI 1.3 launch parameters: {:?}", params);

    // Get the ID token
    let id_token = params.get("id_token").ok_or(StatusCode::BAD_REQUEST)?;
    let state = params.get("state");

    tracing::debug!("ID Token: {}", id_token);
    tracing::debug!("State: {:?}", state);

    // Verify JWT token (simplified - in production you'd verify signature properly)
    match verify_lti13_token(id_token, &lti13_used_nonce_values) {
        Ok(claims) => {
            // Extract user information from claims
            let name = claims.other.get("name")
                .or_else(|| claims.other.get("given_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("LTI 1.3 User")
                .to_string();

            let jar = jar
                .add(Cookie::new("name", name))
                .add(Cookie::new("count", "0"));

            let body = format!("LTI 1.3 Launch successful! User: {:?}, Deployment: {}", 
                             claims.other.get("name").or(claims.other.get("given_name")), 
                             claims.deployment_id);
            
            Ok((jar, body))
        },
        Err(e) => {
            tracing::error!("JWT verification failed: {:?}", e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

fn verify_lti13_token(
    id_token: &str,
    used_nonce_values: &Lti13UsedNonceValues,
) -> Result<Lti13Claims, JwtError> {
    // For a minimal implementation, we'll skip signature verification
    // In production, you should verify the signature using the platform's public key
    
    // Decode without verification for demo purposes
    let mut validation = Validation::new(Algorithm::RS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false; // Skip expiration check for demo

    // Decode the token
    let token_data = decode::<Lti13Claims>(
        id_token,
        &DecodingKey::from_secret(&[]), // Empty key since we're not verifying
        &validation,
    )?;

    let claims = token_data.claims;

    // Check nonce to prevent replay attacks
    {
        let mut nonce_values = used_nonce_values.lock().unwrap();
        nonce_values.retain(|_, time| time.elapsed().as_secs() <= 90 * 60);
        
        if nonce_values.contains_key(&claims.nonce) {
            return Err(JwtError::from(jsonwebtoken::errors::ErrorKind::InvalidToken));
        }
        nonce_values.insert(claims.nonce.clone(), Instant::now());
    }

    // Basic validation
    if claims.message_type != "LtiResourceLinkRequest" {
        return Err(JwtError::from(jsonwebtoken::errors::ErrorKind::InvalidToken));
    }

    if claims.version != "1.3.0" {
        return Err(JwtError::from(jsonwebtoken::errors::ErrorKind::InvalidToken));
    }

    tracing::info!("LTI 1.3 token verified successfully");
    Ok(claims)
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
