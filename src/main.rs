use std::env;
use std::fs;
use std::process;

mod parser;
use parser::{count_by_ip, count_by_user, parse_line, ParseOutcome};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: cargo run -- <log_file>");
        eprintln!("Example: cargo run -- samples/auth_sample.log");
        process::exit(1);
    }

    let filename = &args[1];

    let content = match fs::read_to_string(filename) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading file '{}': {}", filename, e);
            process::exit(1);
        }
    };

    let mut failed_events = Vec::new();
    let mut total_lines = 0;
    let mut malformed_count = 0;
    let mut ignored_count = 0;

    for line in content.lines() {
        total_lines += 1;
        match parse_line(line) {
            ParseOutcome::Failed(login) => {
                failed_events.push(login);
            }
            ParseOutcome::Ignored => {
                ignored_count += 1;
            }
            ParseOutcome::Malformed => {
                malformed_count += 1;
            }
        }
    }

    println!("========================================");
    println!("     TP1 Secure Log Analyzer");
    println!("========================================\n");
    println!("Input file: {}\n", filename);
    println!("Summary:");
    println!("  - Total lines read: {}", total_lines);
    println!("  - Failed login events: {}", failed_events.len());
    println!("  - Ignored lines: {}", ignored_count);
    println!("  - Malformed lines: {}\n", malformed_count);

    println!("Top source IPs:");
    let top_ips = count_by_ip(&failed_events);
    for (i, (ip, count)) in top_ips.iter().enumerate() {
        println!("  {}. {} -> {} failed attempts", i + 1, ip, count);
    }

    println!();

    println!("Top targeted users:");
    let top_users = count_by_user(&failed_events);
    for (i, (user, count)) in top_users.iter().enumerate() {
        println!("  {}. {} -> {} failed attempts", i + 1, user, count);
    }

    println!("\n✅ Analysis complete!");
}
