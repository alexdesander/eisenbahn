use std::net::SocketAddr;

use ed25519_dalek::VerifyingKey;

use crate::common::encryption::{sym::SymCipherAlgorithm, Encryption};

use super::{SendConnectionResponseType, ServerCmd};

pub enum AuthenticationResult {
    Success {
        payload: Vec<u8>,
    },
    Failure {
        /// User defined
        payload: Vec<u8>,
    },
}

pub enum Authenticator {
    None(Box<dyn NoneAuthenticator>),
    Key(Box<dyn KeyAuthenticator>),
    Password(Box<dyn PasswordAuthenticator>),
    CA(Box<dyn CAAuthenticator>),
}

pub trait NoneAuthenticator: Send {
    /// Payload size is limited to 1067 bytes
    fn authenticate(&mut self, player_name: &str) -> AuthenticationResult;
}

pub trait KeyAuthenticator: Send {
    /// Payload size is limited to 1067 bytes
    fn authenticate(
        &mut self,
        player_name: &str,
        player_public_key: VerifyingKey,
    ) -> AuthenticationResult;
}

pub trait PasswordAuthenticator: Send {
    /// Payload size is limited to 1179 bytes
    fn authenticate(&mut self, player_name: &str, password_hash: [u8; 20]) -> AuthenticationResult;
}

pub trait CAAuthenticator: Send {
    /// Payload size is limited to 1067 bytes
    /// Returns the result and in case of success the player name
    fn authenticate(&mut self, ticket: [u8; 32]) -> (AuthenticationResult, Option<String>);
}

pub enum AuthCmd {
    AuthenticateNone {
        addr: SocketAddr,
        salt: u32,
        cipher: SymCipherAlgorithm,
        client_x25519_pub_key: [u8; 32],
        player_name: String,
    },
    AuthenticateKey {
        addr: SocketAddr,
        salt: u32,
        cipher: SymCipherAlgorithm,
        client_x25519_pub_key: [u8; 32],
        player_name: String,
        player_public_key: VerifyingKey,
    },
    AuthenticatePassword {
        addr: SocketAddr,
        salt: u32,
        encryption: Encryption,
        player_name: String,
        password_hash: [u8; 20],
    },
    AuthenticateCA {
        addr: SocketAddr,
        salt: u32,
        cipher: SymCipherAlgorithm,
        client_x25519_pub_key: [u8; 32],
        ticket: [u8; 32],
    },
    Shutdown,
}

pub struct AuthState {
    inner: Authenticator,
    cmds: crossbeam_channel::Receiver<AuthCmd>,
    server_cmds: crossbeam_channel::Sender<ServerCmd>,
}

impl AuthState {
    pub fn new(
        inner: Authenticator,
        cmds: crossbeam_channel::Receiver<AuthCmd>,
        server_cmds: crossbeam_channel::Sender<ServerCmd>,
    ) -> Self {
        Self {
            inner,
            cmds,
            server_cmds,
        }
    }

    pub fn run(&mut self) {
        loop {
            let cmd = match self.cmds.recv() {
                Ok(cmd) => cmd,
                Err(_) => break,
            };
            match cmd {
                AuthCmd::AuthenticateNone {
                    addr,
                    salt,
                    cipher,
                    client_x25519_pub_key,
                    player_name,
                } => match &mut self.inner {
                    Authenticator::None(a) => match a.authenticate(&player_name) {
                        AuthenticationResult::Success { payload } => {
                            if self
                                .server_cmds
                                .send(ServerCmd::SendConnectionResponse {
                                    addr,
                                    cipher,
                                    salt,
                                    client_x25519_pub_key,
                                    response_type: SendConnectionResponseType::Success {
                                        payload,
                                        player_name,
                                    },
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        AuthenticationResult::Failure { payload } => {
                            if self
                                .server_cmds
                                .send(ServerCmd::SendConnectionResponse {
                                    addr,
                                    cipher,
                                    salt,
                                    client_x25519_pub_key,
                                    response_type: SendConnectionResponseType::Failure { payload },
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                    },
                    _ => unreachable!(),
                },
                AuthCmd::AuthenticateKey {
                    addr,
                    salt,
                    cipher,
                    client_x25519_pub_key,
                    player_name,
                    player_public_key,
                } => match &mut self.inner {
                    Authenticator::Key(a) => {
                        match a.authenticate(&player_name, player_public_key) {
                            AuthenticationResult::Success { payload } => {
                                if self
                                    .server_cmds
                                    .send(ServerCmd::SendConnectionResponse {
                                        addr,
                                        cipher,
                                        salt,
                                        client_x25519_pub_key,
                                        response_type: SendConnectionResponseType::Success {
                                            payload,
                                            player_name,
                                        },
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            AuthenticationResult::Failure { payload } => {
                                if self
                                    .server_cmds
                                    .send(ServerCmd::SendConnectionResponse {
                                        addr,
                                        cipher,
                                        salt,
                                        client_x25519_pub_key,
                                        response_type: SendConnectionResponseType::Failure {
                                            payload,
                                        },
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                },
                AuthCmd::AuthenticatePassword {
                    addr,
                    salt,
                    encryption,
                    player_name,
                    password_hash,
                } => match &mut self.inner {
                    Authenticator::Password(a) => {
                        match a.authenticate(&player_name, password_hash) {
                            AuthenticationResult::Success { payload } => {
                                if self
                                    .server_cmds
                                    .send(ServerCmd::SendPasswordResponse {
                                        addr,
                                        salt,
                                        success: true,
                                        encryption,
                                        info: payload,
                                        player_name,
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            AuthenticationResult::Failure { payload } => {
                                if self
                                    .server_cmds
                                    .send(ServerCmd::SendPasswordResponse {
                                        addr,
                                        salt,
                                        success: false,
                                        encryption,
                                        info: payload,
                                        player_name,
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                },
                AuthCmd::AuthenticateCA {
                    addr,
                    salt,
                    cipher,
                    client_x25519_pub_key,
                    ticket,
                } => match &mut self.inner {
                    Authenticator::CA(a) => match a.authenticate(ticket) {
                        (AuthenticationResult::Success { payload }, Some(player_name)) => {
                            if self
                                .server_cmds
                                .send(ServerCmd::SendConnectionResponse {
                                    addr,
                                    cipher,
                                    salt,
                                    client_x25519_pub_key,
                                    response_type: SendConnectionResponseType::Success {
                                        payload,
                                        player_name,
                                    },
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        (AuthenticationResult::Failure { payload }, None) => {
                            if self
                                .server_cmds
                                .send(ServerCmd::SendConnectionResponse {
                                    addr,
                                    cipher,
                                    salt,
                                    client_x25519_pub_key,
                                    response_type: SendConnectionResponseType::Failure { payload },
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                },
                AuthCmd::Shutdown => break,
            }
        }
    }
}
