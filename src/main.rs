use clap::Parser;
use std::process;

fn main() {
    let cli = ficrypt::Cli::parse();
    let key = rpassword::prompt_password("Enter the encryption key: ").unwrap();

    let config = ficrypt::Config::build(cli, key);
    if let Err(e) = ficrypt::run(config) {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}
