mod attest_ext;
mod proxy;
mod tls;

use axum::{
    body::Body,
    extract::State,
    http::Request,
    response::IntoResponse,
    routing::post,
    Router,
};
use clap::Parser;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tower::ServiceExt;

#[derive(Parser, Debug)]
#[command(about = "Sifir RA-TLS gateway — Phase 1 (mock attestation)")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:7443")]
    listen: String,

    /// Inference backend URL (e.g. http://127.0.0.1:8080).
    /// Omit to run without a backend (echo mode for Phase 1 testing).
    #[arg(long)]
    backend: Option<String>,
}

#[derive(Clone)]
struct AppState {
    backend_url: Option<String>,
}

async fn generate_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    proxy::handle_generate(headers, body, state.backend_url.clone()).await
}

async fn health_handler() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("[sifir-server] building TLS setup (mock attestation)...");
    let setup = tls::build_mock_setup().await?;

    println!(
        "[sifir-server] measurement (all-zeros in mock mode): {}",
        hex::encode(setup.measurement)
    );
    println!("[sifir-server] listening on https://{}", args.listen);

    if args.backend.is_none() {
        println!("[sifir-server] no backend configured — echo mode active");
    }

    let state = AppState {
        backend_url: args.backend,
    };

    let app = Router::new()
        .route("/v1/generate", post(generate_handler))
        .route("/health", axum::routing::get(health_handler))
        .with_state(state);

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(setup.server_config);
    let listener = TcpListener::bind(&args.listen).await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[sifir-server] TLS accept error from {peer}: {e}");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let app = app.clone();
                async move {
                    let req = req.map(Body::new);
                    Ok::<_, std::convert::Infallible>(app.oneshot(req).await.unwrap_or_else(|e| {
                        eprintln!("[sifir-server] request error: {e}");
                        axum::http::Response::builder()
                            .status(500)
                            .body(Body::empty())
                            .unwrap()
                    }))
                }
            });

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
            {
                eprintln!("[sifir-server] connection error from {peer}: {e}");
            }
        });
    }
}
