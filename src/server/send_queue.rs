use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use ahash::HashMap;
use crossbeam_channel::TrySendError;
use mio::Waker;
use thiserror::Error;

use super::builder::ToSend;

#[derive(Debug, Error)]
pub enum SendError {
    #[error("The send queue is full for this connection.")]
    SendQueueFull,
    #[error("The server has shut down.")]
    ServerShutdown,
}

#[derive(Clone)]
pub(crate) struct SendQueue {
    inner: Arc<Mutex<SendQueueInner>>,
}

impl SendQueue {
    pub fn new(max_pending_msgs: usize, waker: Arc<Waker>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SendQueueInner::new(max_pending_msgs, waker))),
        }
    }

    pub fn add(&self, addr: SocketAddr) {
        self.inner.lock().unwrap().add(addr);
    }

    pub fn remove(&self, addr: SocketAddr) {
        self.inner.lock().unwrap().remove(addr);
    }

    /// Returns true if should shutdown
    pub fn get_all_to_send(&mut self, buf: &mut Vec<(SocketAddr, ToSend)>) -> bool {
        self.inner.lock().unwrap().get_all_to_send(buf)
    }

    pub fn send(&self, addr: SocketAddr, to_send: ToSend) -> Result<(), SendError> {
        self.inner.lock().unwrap().send(addr, to_send)
    }

    pub fn blocking_send(&self, addr: SocketAddr, to_send: ToSend) -> Result<(), SendError> {
        self.inner.lock().unwrap().blocking_send(addr, to_send)
    }
}

struct SendQueueInner {
    waker: Arc<Waker>,
    max_pending_msgs: usize,
    has_pending: VecDeque<SocketAddr>,
    send_queue_txs: HashMap<SocketAddr, crossbeam_channel::Sender<ToSend>>,
    send_queue_rxs: HashMap<SocketAddr, crossbeam_channel::Receiver<ToSend>>,
}

impl SendQueueInner {
    fn new(max_pending_msgs: usize, waker: Arc<Waker>) -> Self {
        Self {
            waker,
            max_pending_msgs,
            has_pending: VecDeque::new(),
            send_queue_txs: HashMap::default(),
            send_queue_rxs: HashMap::default(),
        }
    }

    pub fn add(&mut self, addr: SocketAddr) {
        assert!(!self.send_queue_txs.contains_key(&addr));
        assert!(!self.send_queue_rxs.contains_key(&addr));
        let (tx, rx) = crossbeam_channel::bounded(self.max_pending_msgs);
        assert!(self.send_queue_txs.insert(addr, tx).is_none());
        assert!(self.send_queue_rxs.insert(addr, rx).is_none());
    }

    pub fn remove(&mut self, addr: SocketAddr) {
        assert!(self.send_queue_txs.remove(&addr).is_some());
        assert!(self.send_queue_rxs.remove(&addr).is_some());
    }

    fn send(&mut self, addr: SocketAddr, to_send: ToSend) -> Result<(), SendError> {
        match self.has_pending.binary_search(&addr) {
            Ok(_) => {}
            Err(i) => {
                self.has_pending.insert(i, addr);
                // TODO: Fix waking and stuff
                let _ = self.waker.wake();
            }
        }
        match self.send_queue_txs.get(&addr).unwrap().try_send(to_send) {
            Ok(_) => Ok(()),
            Err(TrySendError::Full(_)) => Err(SendError::SendQueueFull),
            Err(_) => Err(SendError::ServerShutdown),
        }
    }

    /// This will never return SendError::SendQueueFull
    fn blocking_send(&mut self, addr: SocketAddr, to_send: ToSend) -> Result<(), SendError> {
        match self.has_pending.binary_search(&addr) {
            Ok(_) => {}
            Err(i) => {
                self.has_pending.insert(i, addr);
                // TODO: Fix waking and stuff
                let _ = self.waker.wake();
            }
        }
        match self.send_queue_txs.get(&addr).unwrap().send(to_send) {
            Ok(_) => Ok(()),
            Err(_) => Err(SendError::ServerShutdown),
        }
    }

    /// Returns true if server should be shutdown.
    fn get_all_to_send(&mut self, buf: &mut Vec<(SocketAddr, ToSend)>) -> bool {
        for addr in self.has_pending.drain(..) {
            let to_send_rx = self.send_queue_rxs.get(&addr).unwrap();
            loop {
                match to_send_rx.try_recv() {
                    Ok(to_send) => buf.push((addr, to_send)),
                    Err(crossbeam_channel::TryRecvError::Empty) => break,
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        return true;
                    }
                }
            }
        }
        false
    }
}
