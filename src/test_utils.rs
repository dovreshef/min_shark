use std::sync::Once;
use tracing_subscriber::EnvFilter;

static INIT_LOGGER: Once = Once::new();

/// This must be called from every test, so the logging will show up
pub fn init_test_logging() {
    INIT_LOGGER.call_once(|| {
        tracing_subscriber::fmt::fmt()
            .with_env_filter(EnvFilter::new("debug"))
            .init();
    });
}
