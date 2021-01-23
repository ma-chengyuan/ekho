use crate::relay::relay_kcp;
use crate::session::Session;
use crate::socks5::{Socks5Command, Socks5Error, Socks5Reply, Socks5Request};
use anyhow::Result;
use tokio::task;
use tracing::{debug, error, instrument};

#[instrument]
async fn handle_request(session: Session) -> Result<()> {
    let request = Socks5Request::parse(&session.recv().await)?;
    debug!("{:?}", request);
    match request.cmd {
        Socks5Command::Connect => match request.dst.connect().await {
            Ok(remote) => {
                session
                    .send(
                        &Socks5Reply::Success {
                            bnd: remote.local_addr()?.into(),
                        }
                        .marshal(),
                    )
                    .await;
                relay_kcp(remote, session).await?;
            }
            Err(err) => {
                error!(
                    "error while connecting to remote host {}: {}",
                    request.dst, err
                );
                session
                    .send(&Socks5Reply::Error(err.into()).marshal())
                    .await;
                session.close().await;
            }
        },
        _ => {
            session
                .send(&Socks5Reply::Error(Socks5Error::CommandNotSupported).marshal())
                .await;
            session.close().await;
        }
    }
    Ok(())
}

#[instrument]
pub async fn run() {
    loop {
        let kcp = Session::incoming().await;
        task::spawn(async move {
            if let Err(err) = handle_request(kcp).await {
                error!("{}", err);
            }
        });
    }
}
