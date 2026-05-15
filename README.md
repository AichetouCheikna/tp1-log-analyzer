# TP1 - Secure Log Analyzer

## Objective
Analyze SSH authentication logs to detect suspicious login activity.

## Environment Requirements
- Docker Compose
- Rust (inside container)

## Build & Run
```bash
docker-compose up -d
docker exec -it rust-tp1 bash
cd /workspace/tp1_log_analyzer
cargo run -- samples/auth_sample.log
cargo test
cargo fmt
cargo clippy -- -D warnings
TP1 Student
