use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedLogin {
    pub user: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Failed(FailedLogin),
    Ignored,
    Malformed,
}

pub fn parse_line(line: &str) -> ParseOutcome {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ParseOutcome::Malformed;
    }
    
    if line.contains("MALFORMED") {
        return ParseOutcome::Malformed;
    }
    
    if !line.contains("sshd") {
        return ParseOutcome::Ignored;
    }
    
    if line.contains("Accepted") {
        return ParseOutcome::Ignored;
    }
    
    if line.contains("Failed password") {
        let user = if line.contains("invalid user") {
            extract_username_invalid(line)
        } else {
            extract_username_normal(line)
        };
        let ip = extract_ip(line);
        
        if let (Some(user), Some(ip)) = (user, ip) {
            return ParseOutcome::Failed(FailedLogin { user, ip });
        }
    }
    
    if line.contains("Invalid user") {
        let user = extract_invalid_user_only(line);
        let ip = extract_ip(line);
        
        if let (Some(user), Some(ip)) = (user, ip) {
            return ParseOutcome::Failed(FailedLogin { user, ip });
        }
    }
    
    ParseOutcome::Ignored
}

fn extract_username_normal(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "for" && i + 1 < parts.len() {
            let user = parts[i + 1];
            if !user.contains("invalid") && !user.contains("from") {
                return Some(user.to_string());
            }
        }
    }
    None
}

fn extract_username_invalid(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "user" && i + 1 < parts.len() {
            let user = parts[i + 1];
            if user != "from" {
                return Some(user.to_string());
            }
        }
    }
    None
}

fn extract_invalid_user_only(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "user" && i + 1 < parts.len() {
            let user = parts[i + 1];
            if user != "from" && !user.contains("port") {
                return Some(user.to_string());
            }
        }
    }
    None
}

fn extract_ip(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "from" && i + 1 < parts.len() {
            let ip = parts[i + 1];
            if ip.contains('.') && !ip.contains("port") {
                return Some(ip.to_string());
            }
        }
    }
    None
}

pub fn count_by_ip(events: &[FailedLogin]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    
    for event in events {
        *counts.entry(event.ip.clone()).or_insert(0) += 1;
    }
    
    let mut result: Vec<(String, usize)> = counts.into_iter().collect();
    result.sort_by_key(|b| std::cmp::Reverse(b.1));
    result
}

pub fn count_by_user(events: &[FailedLogin]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    
    for event in events {
        *counts.entry(event.user.clone()).or_insert(0) += 1;
    }
    
    let mut result: Vec<(String, usize)> = counts.into_iter().collect();
    result.sort_by_key(|b| std::cmp::Reverse(b.1));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_failed_password_normal() {
        let line = "Jan 10 08:16:03 srvo1 sshd[1002]: Failed password for root from 198.51.100.23 port 55432 ssh2";
        let result = parse_line(line);
        match result {
            ParseOutcome::Failed(fl) => {
                assert_eq!(fl.user, "root");
                assert_eq!(fl.ip, "198.51.100.23");
            }
            _ => panic!("Expected Failed outcome"),
        }
    }

    #[test]
    fn test_parse_failed_password_invalid_user() {
        let line = "Jan 10 08:15:21 srvo1 sshd[1001]: Failed password for invalid user admin from 203.0.113.10 port 34567 ssh2";
        let result = parse_line(line);
        match result {
            ParseOutcome::Failed(fl) => {
                assert_eq!(fl.user, "admin");
                assert_eq!(fl.ip, "203.0.113.10");
            }
            _ => panic!("Expected Failed outcome"),
        }
    }

    #[test]
    fn test_parse_accepted_login_ignored() {
        let line = "Jan 10 08:16:44 srvo1 sshd[1003]: Accepted password for student from 192.0.2.15 port 44822 ssh2";
        let result = parse_line(line);
        assert_eq!(result, ParseOutcome::Ignored);
    }

    #[test]
    fn test_parse_malformed_line() {
        let line = "MALFORMED LINE WITHOUT EXPECTED SSH FIELDS";
        let result = parse_line(line);
        assert_eq!(result, ParseOutcome::Malformed);
    }

    #[test]
    fn test_parse_invalid_user_line() {
        let line = "Jan 10 08:19:41 srvo1 sshd[1006]: Invalid user oracle from 192.0.2.55 port 51200";
        let result = parse_line(line);
        match result {
            ParseOutcome::Failed(fl) => {
                assert_eq!(fl.user, "oracle");
                assert_eq!(fl.ip, "192.0.2.55");
            }
            _ => panic!("Expected Failed outcome"),
        }
    }

    #[test]
    fn test_count_by_ip() {
        let events = vec![
            FailedLogin { user: "root".to_string(), ip: "1.1.1.1".to_string() },
            FailedLogin { user: "admin".to_string(), ip: "1.1.1.1".to_string() },
            FailedLogin { user: "test".to_string(), ip: "2.2.2.2".to_string() },
        ];
        let counts = count_by_ip(&events);
        assert_eq!(counts[0], ("1.1.1.1".to_string(), 2));
        assert_eq!(counts[1], ("2.2.2.2".to_string(), 1));
    }

    #[test]
    fn test_count_by_user() {
        let events = vec![
            FailedLogin { user: "root".to_string(), ip: "1.1.1.1".to_string() },
            FailedLogin { user: "root".to_string(), ip: "2.2.2.2".to_string() },
            FailedLogin { user: "admin".to_string(), ip: "3.3.3.3".to_string() },
        ];
        let counts = count_by_user(&events);
        assert_eq!(counts[0], ("root".to_string(), 2));
        assert_eq!(counts[1], ("admin".to_string(), 1));
    }
}
