use axum::{
    routing::get,
    Router,
};
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
