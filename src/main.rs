use axum::{
    extract::Form,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/lti", post(lti))
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

#[derive(Debug, Deserialize)]
struct LtiPayload {
    oauth_version: String,
    oauth_nonce: String,
    oauth_timestamp: String,
    oauth_consumer_key: String,
    user_id: String,
    lis_person_sourcedid: String,
    roles: String,
    context_id: String,
    context_label: String,
    context_title: String,
    resource_link_title: String,
    resource_link_description: String,
    resource_link_id: String,
    context_type: String,
    lis_course_section_sourcedid: String,
    lis_result_sourcedid: String,
    lis_outcome_service_url: String,
    lis_person_name_given: String,
    lis_person_name_family: String,
    lis_person_name_full: String,
    ext_user_username: String,
    lis_person_contact_email_primary: String,
    launch_presentation_locale: String,
    ext_lms: String,
    tool_consumer_info_product_family_code: String,
    tool_consumer_info_version: String,
    oauth_callback: String,
    lti_version: String,
    lti_message_type: String,
    tool_consumer_instance_guid: String,
    tool_consumer_instance_name: String,
    tool_consumer_instance_description: String,
    launch_presentation_document_target: String,
    launch_presentation_return_url: String,
    oauth_signature_method: String,
    oauth_signature: String,
}

async fn lti(Form(payload): Form<LtiPayload>) -> impl IntoResponse {
    tracing::debug!("/lti accessed");
    tracing::debug!("{:?}", payload);
    "LTI"
}
