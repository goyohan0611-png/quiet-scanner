use super::*;
use std::process::{Command, Stdio};

fn response_ms(text: &str) -> Option<u64> {
    let offset = text.find("time=").or_else(|| text.find("time<"))? + 5;
    let number: String = text[offset..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let value = number.parse::<f64>().ok()?;
    (value.is_finite() && (0.0..=60000.0).contains(&value)).then_some(value.round() as u64)
}
pub fn ping(source: Ipv4Addr, target: Ipv4Addr) -> Result<ResultRow, String> {
    #[cfg(target_os = "linux")]
    let paths = ["/usr/bin/ping", "/bin/ping"];
    #[cfg(target_os = "macos")]
    let paths = ["/sbin/ping", "/usr/sbin/ping"];
    let executable = paths
        .iter()
        .find(|p| std::path::Path::new(p).is_file())
        .ok_or("Ping 도구가 없습니다. Linux에서는 iputils-ping을 설치하십시오.")?;
    let mut command = Command::new(executable);
    command.env("LC_ALL", "C").args(["-n", "-c", "1", "-W"]);
    #[cfg(target_os = "linux")]
    command.args(["1", "-I", &source.to_string(), "--", &target.to_string()]);
    #[cfg(target_os = "macos")]
    command.args(["800", "-S", &source.to_string(), &target.to_string()]);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_millis(1500);
    let timed_out = loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let ms = response_ms(&text);
    let ok = !timed_out && output.status.success() && ms.is_some();
    let (status, message) = if ok {
        ("reply", "응답 받음")
    } else if text.contains("unreachable") || text.contains("No route") {
        (
            "unreachable",
            "대상 또는 네트워크 경로에 도달할 수 없습니다",
        )
    } else if text.contains("Operation not permitted") || text.contains("Permission denied") {
        ("blocked", "이 PC에서 Ping 요청이 차단됐습니다")
    } else if timed_out || output.status.code() == Some(1) || output.status.code() == Some(2) {
        ("timeout", "응답 시간 초과")
    } else {
        ("error", "Ping 도구의 응답을 확인하지 못했습니다")
    };
    Ok(ResultRow {
        ip: target.to_string(),
        port: None,
        ok,
        status,
        message: message.into(),
        ms: ok.then_some(ms).flatten(),
        code: (!ok).then(|| output.status.code().unwrap_or(-1) as u32),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_native_reply_timing_without_using_process_startup_time() {
        assert_eq!(
            response_ms("64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.037 ms"),
            Some(0)
        );
        assert_eq!(response_ms("time=12.6 ms"), Some(13));
        assert_eq!(response_ms("time<1 ms"), Some(1));
        assert_eq!(response_ms("100% packet loss"), None);
    }
}
