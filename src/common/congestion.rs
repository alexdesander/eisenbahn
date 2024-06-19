// TODO
use std::time::{Duration, Instant};

pub struct CongestionController {
    latency: Duration,

    send_cool_down: Duration,

    // Only for reliable messages
    max_in_flight: u8,
    resend_cool_down: Duration,
}

impl CongestionController {
    pub fn update_latency(&mut self, latency: Duration) {
        let latency_secs = latency.as_secs_f64();
        let old_latency_secs = self.latency.as_secs_f64();

        self.resend_cool_down = (latency + self.latency) / 2;

        if old_latency_secs * 1.2 <= latency_secs {
            self.go_slower(latency_secs / old_latency_secs);
        } else if old_latency_secs / 1.25 >= latency_secs {
            self.go_faster(old_latency_secs / latency_secs);
        }
    }

    fn go_slower(&mut self, factor: f64) {
        self.send_cool_down = Duration::from_secs_f64(self.send_cool_down.as_secs_f64() * factor);
    }

    fn go_faster(&mut self, factor: f64) {
        self.send_cool_down = Duration::from_secs_f64(self.send_cool_down.as_secs_f64() / factor);
    }
}
