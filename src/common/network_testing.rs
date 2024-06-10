use std::{
    collections::BinaryHeap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use crossbeam_channel::RecvTimeoutError;
use mio::net::UdpSocket;

use super::socket::{NetworkCircumstances, PerfectNetworkCircumstances};

pub(crate) struct TimedEvent {
    deadline: Instant,
    event: Event,
}

impl PartialEq for TimedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl Eq for TimedEvent {}

impl PartialOrd for TimedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(other.deadline.cmp(&self.deadline))
    }
}

impl Ord for TimedEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.deadline.cmp(&self.deadline)
    }
}

pub(crate) enum Event {
    SendPacket(SocketAddr, Vec<u8>),
}

pub struct NetworkTesting {
    inner: Box<dyn NetworkCircumstances>,
    to_send_tx: crossbeam_channel::Sender<(SocketAddr, Vec<u8>, Duration)>,
    send_thread: JoinHandle<()>,
}

impl NetworkTesting {
    pub fn new(socket: Arc<Mutex<UdpSocket>>, inner: Box<dyn NetworkCircumstances>) -> Self {
        let (to_send_tx, to_send_rx) = crossbeam_channel::unbounded();
        let send_thread = std::thread::spawn(move || {
            let mut timed_events: BinaryHeap<TimedEvent> = BinaryHeap::new();
            loop {
                if let Some(next_event) = timed_events.peek() {
                    match to_send_rx.recv_deadline(next_event.deadline) {
                        Ok((addr, data, delay)) => {
                            timed_events.push(TimedEvent {
                                deadline: Instant::now() + delay,
                                event: Event::SendPacket(addr, data),
                            });
                            continue;
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                } else {
                    let Ok((addr, data, delay)) = to_send_rx.recv() else {
                        break;
                    };
                    timed_events.push(TimedEvent {
                        deadline: Instant::now() + delay,
                        event: Event::SendPacket(addr, data),
                    });
                }

                loop {
                    let socket = socket.lock().unwrap();
                    let Some(event) = timed_events.peek() else {
                        break;
                    };
                    if event.deadline > Instant::now() {
                        break;
                    }
                    let event = timed_events.pop().unwrap();
                    match event.event {
                        Event::SendPacket(addr, data) => {
                            socket.send_to(&data, addr).unwrap();
                        }
                    }
                }
            }
        });
        NetworkTesting {
            inner,
            to_send_tx,
            send_thread,
        }
    }

    pub fn send(&mut self, addr: SocketAddr, data: Vec<u8>) {
        if self.inner.simulate_packet_loss(data.len()) {
            return;
        }
        let delay = self.inner.simulate_packet_latency(data.len());
        self.to_send_tx.send((addr, data, delay)).unwrap();
    }
}
