mod attest_ext;
mod proxy;
mod tls;

#[cfg(feature = "real-attestation")]
mod amd_attestation;

#[cfg(feature = "gpu-cc")]
mod gpu_attestation;

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
#[command(about = "Sifir RA-TLS gateway")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:7443")]
    listen: String,

    /// Inference backend URL (e.g. http://127.0.0.1:8080).
    /// Omit to run without a backend (echo mode for Phase 1 testing).
    #[arg(long)]
    backend: Option<String>,

    /// Use real AMD SEV-SNP attestation (requires --features real-attestation
    /// and /dev/snp-guest). Omit to use mock attestation (Phases 1–2).
    #[arg(long, default_value_t = false)]
    amd: bool,

    /// AMD product name for KDS cert chain lookup.
    /// Azure DCasv5 = "Milan", Azure NCC H100 v5 = "Genoa".
    #[arg(long, default_value = "Milan")]
    snp_product: String,

    /// Append NVIDIA GPU CC attestation JWT to the TLS cert extension.
    /// Requires --amd, --features gpu-cc, and the NVIDIA attestation SDK.
    #[arg(long, default_value_t = false)]
    gpu_cc: bool,

    /// Path to poc/inference/gpu_attest.py.
    /// Required when --gpu-cc is set.
    #[arg(long)]
    gpu_attest_script: Option<String>,
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

    let setup = match (args.amd, args.gpu_cc) {
        (false, _) => {
            println!("[sifir-server] building TLS setup (mock attestation)...");
            tls::build_mock_setup().await?
        }
        (true, false) => {
            #[cfg(feature = "real-attestation")]
            {
                println!(
                    "[sifir-server] building TLS setup (AMD SEV-SNP, product={})...",
                    args.snp_product
                );
                tls::build_amd_setup(&args.snp_product).await?
            }
            #[cfg(not(feature = "real-attestation"))]
            {
                anyhow::bail!("--amd requires compiling with `--features real-attestation`");
            }
        }
        (true, true) => {
            #[cfg(all(feature = "real-attestation", feature = "gpu-cc"))]
            {
                let script = args.gpu_attest_script.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("--gpu-cc requires --gpu-attest-script <path>")
                })?;
                println!(
                    "[sifir-server] building TLS setup (AMD SEV-SNP + GPU CC, product={})...",
                    args.snp_product
                );
                tls::build_amd_gpu_setup(&args.snp_product, script).await?
            }
            #[cfg(not(all(feature = "real-attestation", feature = "gpu-cc")))]
            {
                anyhow::bail!(
                    "--gpu-cc requires compiling with `--features real-attestation,gpu-cc`"
                );
            }
        }
    };

    println!(
        "[sifir-server] measurement: {}",
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
