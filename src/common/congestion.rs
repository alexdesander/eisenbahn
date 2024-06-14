use std::time::Duration;

pub struct CongestionController {
    latest_latency: Duration,

    send_cool_down: Duration,

    // Only for reliable messages
    max_in_flight: u8,
    resend_cool_down: Duration,
}

impl CongestionController {
    pub fn update_latency(&mut self, latency: Duration) {}
}
