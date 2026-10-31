#[cfg(windows)]
mod windows_sensor;

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows_sensor::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the SentinelForge Windows sensor can only run on Windows");
}
