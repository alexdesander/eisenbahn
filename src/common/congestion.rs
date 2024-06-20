use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub struct CongestionController {
    accelerate_fast: bool,
    start: Instant,
    last_accelerate: Instant,
    last_decelerate: Instant,
    accelerated_once: bool,

    // Measured
    total_sent: u64,
    total_dropped: u64,
    last_total_dropped_reset: Instant,
    pub latest_latency: Duration,
    packet_losses: VecDeque<(u32, u32)>, // (sent, lost), every entry is 1 second
    last_packet_loss_index: u8,

    target_bandwidth: u32, // in bytes per second

    // Derived from the bandwidth
    pub base_send_cooldown: u32, // If sending 1 byte (in microseconds)
    pub packet_resend_cooldown: u32, // If sending 1 byte (in milliseconds)
    pub max_in_flight: u16,
}

impl CongestionController {
    pub fn new() -> Self {
        let target_bandwidth = 64000;
        Self {
            start: Instant::now(),
            last_accelerate: Instant::now(),
            last_decelerate: Instant::now(),
            accelerated_once: false,
            total_sent: 0,
            total_dropped: 0,
            last_total_dropped_reset: Instant::now(),
            packet_losses: VecDeque::with_capacity(4),
            accelerate_fast: true,
            latest_latency: Duration::from_millis(100),
            target_bandwidth,
            base_send_cooldown: 1000000 / target_bandwidth,
            packet_resend_cooldown: 150,
            max_in_flight: 8,
            last_packet_loss_index: 0,
        }
    }

    /// Returns true if accelerated/decelerated
    pub fn update_latency(&mut self, latency: Duration) -> bool {
        if self.last_total_dropped_reset.elapsed().as_secs() > 60 {
            self.total_dropped = 0;
            self.total_sent = 50;
        }
        let latency_s = latency.as_secs_f32().max(0.001);
        let latest_latency_s = self.latest_latency.as_secs_f32().max(0.001);

        self.latest_latency = latency;
        if latency_s <= latest_latency_s {
            self.latest_latency = latency;
            if self.accelerate_fast {
                self.fast_accelerate();
                return true;
            } else {
                if self.last_decelerate.elapsed().as_secs() > 8 {
                    self.accelerate();
                    return true;
                }
            }
        } else if latency_s > latest_latency_s * 1.15 {
            self.accelerate_fast = false;
            self.decelerate();
            return true;
        }
        false
    }

    /// Returns true if accelerated/decelerated
    pub fn packet_lost(&mut self) -> bool {
        self.total_dropped += 1;
        if self.accelerate_fast {
            self.accelerate_fast = false;
            self.decelerate();
            return true;
        }
        if self.packet_losses.is_empty() {
            return false;
        }
        self.packet_losses[0].1 += 1;
        let (sent, lost) = self.packet_losses[0];
        let current_loss_rate = (lost + 1) as f32 / (sent + 1) as f32;
        let smoothed_loss_rate = self
            .packet_losses
            .iter()
            .skip(1)
            .fold(0.0, |acc, (s, l)| acc + *l as f32 / *s as f32)
            / 3.0;
        if current_loss_rate > smoothed_loss_rate * 2.0
            && self.last_decelerate.elapsed().as_millis() > 750
            && current_loss_rate * 0.9 > self.total_dropped as f32 / self.total_sent as f32
        {
            self.decelerate();
            return true;
        }
        false
    }

    /// Returns true if accelerated/decelerated
    pub fn packet_sent(&mut self) -> bool {
        self.total_sent += 1;
        let now = Instant::now();
        let elapsed = now - self.start;
        let index = (elapsed.as_secs() % 4) as u8;
        if self.packet_losses.is_empty() {
            self.packet_losses.push_front((0, 0));
        }
        if index != self.last_packet_loss_index {
            self.packet_losses.truncate(3);
            self.packet_losses.push_front((1, 0));
        } else {
            self.packet_losses[0].0 += 1;
        }
        self.last_packet_loss_index = index;

        if self.last_accelerate.elapsed().as_millis() > 1500 {
            if self.accelerate_fast {
                self.fast_accelerate();
                return true;
            } else {
                if self.last_decelerate.elapsed().as_secs() > 8 {
                    self.accelerate();
                    return true;
                }
            }
        }
        false
    }

    fn fast_accelerate(&mut self) {
        self.target_bandwidth += 38400 * 4;
        self.derive();
        if self.accelerated_once {
            self.accelerated_once = false;
        }
        self.last_accelerate = Instant::now();
    }

    fn accelerate(&mut self) {
        self.target_bandwidth += 3600 * 2;
        self.target_bandwidth = self.target_bandwidth.min(16777216); // 16MiB/s
        self.derive();
        if self.accelerated_once {
            self.accelerated_once = false;
        }
        self.last_accelerate = Instant::now();
    }

    fn decelerate(&mut self) {
        if self.target_bandwidth >= 512000 {
            self.target_bandwidth *= 8;
            self.target_bandwidth /= 11;
        } else if self.target_bandwidth >= 128000 {
            self.target_bandwidth -= 38400;
        } else {
            self.target_bandwidth = self.target_bandwidth.saturating_sub(10000).max(4800);
        }
        self.derive();
        self.accelerated_once = false;
        self.last_decelerate = Instant::now();
    }

    fn derive(&mut self) {
        let target_bandwidth = self.target_bandwidth;
        let latest_latency: u32 = self.latest_latency.as_millis().try_into().unwrap();

        self.base_send_cooldown = 1000000 / target_bandwidth;
        self.packet_resend_cooldown = latest_latency + 40;
        self.max_in_flight = (target_bandwidth / 1200).min(1280) as u16;
    }
}
