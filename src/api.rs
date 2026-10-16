use std::{path::PathBuf, process::ExitStatus, str::FromStr as _};

use anyhow::bail;
use iroh::{RelayUrl, SecretKey};

use crate::{
    IrohSsh,
    cli::{ConnectArgs, ProxyArgs, ServerArgs},
    dot_ssh,
};

fn parse_relay_urls(urls: &[String]) -> anyhow::Result<Vec<RelayUrl>> {
    urls.iter()
        .map(|s| RelayUrl::from_str(s).map_err(|e| anyhow::anyhow!("invalid relay URL '{s}': {e}")))
        .collect()
}

pub async fn info_mode(key_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let server_key = dot_ssh(&SecretKey::generate(), false, false, key_dir.as_deref()).ok();
    let service_key = dot_ssh(&SecretKey::generate(), false, true, key_dir.as_deref()).ok();

    if server_key.is_none() && service_key.is_none() {
        println!(
            "No keys found, run for server or service:\n  'iroh-ssh server --persist' or '-p' to create it"
        );
        println!();
        println!("(if an iroh-ssh instance is currently running, it is using ephemeral keys)");
        bail!("No keys found")
    }

    println!("iroh-ssh version {}", env!("CARGO_PKG_VERSION"));
    println!("https://github.com/rustonbsd/iroh-ssh");
    println!();

    if server_key.is_none() && service_key.is_none() {
        println!("run 'iroh-ssh server --persist' to start the server with persistent keys");
        println!("run 'iroh-ssh server' to start the server with ephemeral keys");
        println!(
            "run 'iroh-ssh service install' to copy the binary, install the service and start the server (always uses persistent keys)"
        );
    }

    if let Some(key) = server_key {
        println!();
        println!("Your server iroh-ssh endpoint id:");
        println!(
            "  iroh-ssh {}@{}",
            whoami::username().unwrap_or("UNKNOWN_USER".to_string()),
            key.clone().public()
        );
        println!();
    }

    if let Some(key) = service_key {
        println!();
        println!("Your service iroh-ssh endpoint id:");
        println!(
            "  iroh-ssh {}@{}",
            whoami::username().unwrap_or("UNKNOWN_USER".to_string()),
            key.clone().public()
        );
        println!();
    }

    Ok(())
}

pub mod service {
    use std::path::PathBuf;

    use crate::{ServiceParams, api::abs_key_dir, install_service, uninstall_service};

    pub async fn install(
        ssh_port: u16,
        key_dir: Option<PathBuf>,
        relay_url: Vec<String>,
        extra_relay_url: Vec<String>,
    ) -> anyhow::Result<()> {
        if install_service(ServiceParams {
            ssh_port,
            key_dir: abs_key_dir(key_dir),
            relay_url,
            extra_relay_url,
        })
        .await
        .is_err()
        {
            anyhow::bail!("service install is only supported on linux and windows");
        }
        Ok(())
    }

    pub async fn uninstall() -> anyhow::Result<()> {
        if uninstall_service().await.is_err() {
            println!("service uninstall is only supported on linux or windows");
            anyhow::bail!("service uninstall is only supported on linux or windows");
        }
        Ok(())
    }
}

pub async fn server_mode(server_args: ServerArgs, service: bool) -> anyhow::Result<()> {
    let mut iroh_ssh_builder = IrohSsh::builder()
        .accept_incoming(true)
        .accept_port(server_args.ssh_port)
        .key_dir(server_args.key_dir.clone())
        .relay_urls(parse_relay_urls(&server_args.relay_url)?)
        .extra_relay_urls(parse_relay_urls(&server_args.extra_relay_url)?);
    if server_args.persist {
        iroh_ssh_builder = iroh_ssh_builder.dot_ssh_integration(true, service);
    }
    let iroh_ssh = iroh_ssh_builder.build().await?;

    println!("Connect to this this machine:");
    println!(
        "\n  iroh-ssh {}@{}\n",
        whoami::username().unwrap_or("UNKNOWN_USER".to_string()),
        iroh_ssh.endpoint_id()
    );
    if server_args.persist {
        let ssh_dir = crate::ssh::ssh_dir(server_args.key_dir.as_deref())?;
        println!("  (using persistent keys in {})", ssh_dir.display());
    } else {
        println!(
            "  warning: (using ephemeral keys, run 'iroh-ssh server --persist' to create persistent keys)"
        );
    }
    println!();
    println!(
        "client -> iroh-ssh -> direct connect -> iroh-ssh -> local ssh :{}",
        server_args.ssh_port
    );

    println!("Waiting for incoming connections...");
    println!("Press Ctrl+C to exit");
    #[cfg(unix)]
    {
        let sock = iroh_ssh.spawn_proxy_listener(server_args.key_dir.as_deref())?;
        println!("  proxy socket {}", sock.display());
    }
    tokio::signal::ctrl_c().await?;
    #[cfg(unix)]
    {
        if let Ok(sock) = crate::ssh::proxy_socket_path(server_args.key_dir.as_deref()) {
            let _ = std::fs::remove_file(sock);
        }
    }
    Ok(())
}

pub async fn proxy_mode(proxy_args: ProxyArgs) -> anyhow::Result<()> {
    let hostname = proxy_args
        .endpoint_id
        .split(":")
        .next()
        .ok_or_else(|| anyhow::anyhow!("failed to parse hostname"))?;
    if hostname.len() == 64 && hostname.chars().all(|c| c.is_ascii_hexdigit()) {
        #[cfg(unix)]
        {
            return proxy_through_server(proxy_args.key_dir.as_deref(), hostname).await;
        }
        #[cfg(not(unix))]
        {
            bail!("iroh-ssh proxy requires the unix server socket");
        }
    }
    copy_tcp(&proxy_args.endpoint_id).await
}

async fn copy_tcp(host_addr: &str) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let conn = tokio::net::TcpStream::connect(host_addr).await?;
    let (mut tcp_read, mut tcp_write) = conn.into_split();
    let (mut local_read, mut local_write) = (tokio::io::stdin(), tokio::io::stdout());
    let a_to_b = async move {
        let res = tokio::io::copy(&mut local_read, &mut tcp_write).await;
        tcp_write.shutdown().await.ok();
        res
    };
    let b_to_a = async move { tokio::io::copy(&mut tcp_read, &mut local_write).await };
    let (a_to_b, b_to_a) = tokio::join!(a_to_b, b_to_a);
    a_to_b?;
    b_to_a?;
    Ok(())
}

#[cfg(unix)]
async fn proxy_through_server(
    key_dir: Option<&std::path::Path>,
    hostname: &str,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let sock = crate::ssh::proxy_socket_path(key_dir)?;
    let mut stream = tokio::net::UnixStream::connect(&sock)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "iroh-ssh server is not listening on {}: {err}",
                sock.display()
            )
        })?;
    stream.write_all(format!("{hostname}\n").as_bytes()).await?;
    let (mut read, mut write) = stream.into_split();
    let (mut stdin, mut stdout) = (tokio::io::stdin(), tokio::io::stdout());
    let to_server = async move { tokio::io::copy(&mut stdin, &mut write).await };
    let from_server = async move { tokio::io::copy(&mut read, &mut stdout).await };
    let (to_server, from_server) = tokio::join!(to_server, from_server);
    to_server?;
    from_server?;
    Ok(())
}

pub async fn client_mode(connect_args: ConnectArgs) -> anyhow::Result<()> {
    let mut ssh_process = match crate::ssh::spawn_ssh(
        connect_args.target,
        connect_args.ssh,
        connect_args.remote_cmd,
        &connect_args.relay_url,
        &connect_args.extra_relay_url,
    )
    .await
    {
        Ok(child) => child,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                eprintln!(
                    "SSH command not found, please make sure your system has an SSH client installed and and that the exact cmd \"ssh\" is in your PATH"
                );
                std::process::exit(1);
            }
            _ => {
                eprintln!("Unknown failure when calling the SSH client: {err}");
                std::process::exit(1);
            }
        },
    };

    let status = ssh_process.wait().await?;

    // this kills the process (ok is just here for no compile errors)
    exit_with_code(status);

    Ok(())
}

#[cfg(unix)]
pub(crate) fn exit_with_code(status: ExitStatus) {
    use std::os::unix::process::ExitStatusExt;

    if let Some(code) = status.code() {
        std::process::exit(code);
    }

    // if ssh gets killed locally
    if let Some(sig) = status.signal() {
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::kill(libc::getpid(), sig);
        }
        // fallback if kill fails (same as windows)
        std::process::exit(128 + sig);
    }

    // fallback to 1 if don't know
    std::process::exit(1);
}

#[cfg(not(unix))]
pub(crate) fn exit_with_code(status: ExitStatus) {
    std::process::exit(status.code().unwrap_or(1));
}

pub(crate) fn abs_key_dir(key_dir: Option<PathBuf>) -> Option<PathBuf> {
    key_dir.map(|key_dir| {
        if key_dir.is_absolute() {
            key_dir
        } else {
            std::env::current_dir().unwrap_or_default().join(key_dir)
        }
    })
}
