use clap::{value_t, App, Arg};
use error_chain::error_chain;
use reqwest::Client;
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio;
use url::Url;

error_chain! {
    foreign_links {
        ReqError(reqwest::Error);
        ParseError(url::ParseError);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::new("Check IP or HOSTNAME in RKN blocking")
        .version("0.1.0")
        .arg(
            Arg::with_name("STRING")
                .index(1)
                .multiple(false)
                .required(true),
        );

    let matches = match app.get_matches_from_safe(std::env::args_os().into_iter()) {
        Ok(m) => m,
        Err(ref e)
            if e.kind == clap::ErrorKind::HelpDisplayed
                || e.kind == clap::ErrorKind::VersionDisplayed =>
        {
            println!("{}", e);
            std::process::exit(0);
        }
        Err(f) => {
            eprintln!("{}", f);
            std::process::exit(1)
        }
    };

    let str = value_t!(matches, "STRING", String).unwrap_or_else(|e| e.exit());
    let str = str.to_lowercase();
    let mut ips = Vec::new();
    let mut hostname_blocked = false;
    if str.parse::<Ipv4Addr>().is_ok() || str.parse::<Ipv6Addr>().is_ok() {
        ips.push(str.to_string());
    } else {
        let blocklist_hostname = get_blocklist_hostnames().await?;
        for hostname in blocklist_hostname {
            if hostname.to_lowercase().contains(&str) {
                hostname_blocked = true;
                break;
            }
        }
        let mut ips_blocked = get_ips(&str).await?;
        ips.append(&mut ips_blocked);
    }
    let blocklist_ip = get_blocklist_ips().await?;
    let ip_blocked = ips.iter().any(|ip| blocklist_ip.contains(&ip));

    println!("block: {}", ip_blocked || hostname_blocked);

    Ok(())
}

async fn get_blocklist_ips() -> Result<Vec<String>> {
    let url = Url::parse("https://reestr.rublacklist.net/api/v2/ips/json/")?;
    let client = Client::new();

    let ips: Vec<String> = client.get(url).send().await?.json().await?;

    Ok(ips)
}

async fn get_blocklist_hostnames() -> Result<Vec<String>> {
    let url = Url::parse("https://reestr.rublacklist.net/api/v2/domains/json/")?;
    let client = Client::new();

    let ips: Vec<String> = client.get(url).send().await?.json().await?;

    Ok(ips)
}

async fn get_ips(hostname: &str) -> Result<Vec<String>> {
    let url = Url::parse_with_params(
        "https://dns.google.com/resolve",
        &[
            ("name", hostname),
            ("type", "1"),
            ("cd", "false"),
            ("do", "false"),
        ],
    )?;
    let client = Client::new();

    let dns_summar: DnsSummar = client.get(url).send().await?.json().await?;

    match dns_summar.answers {
        Some(answers) => Ok(answers.iter().map(|a| a.data.clone()).collect()),
        None => Ok(vec![]),
    }
}

#[derive(Deserialize, Debug)]
pub struct DnsSummar {
    #[serde(rename = "Status")]
    pub status: i32,
    #[serde(rename = "TC")]
    pub tc: bool,
    #[serde(rename = "RD")]
    pub rd: bool,
    #[serde(rename = "RA")]
    pub ra: bool,
    #[serde(rename = "AD")]
    pub ad: bool,
    #[serde(rename = "CD")]
    pub cd: bool,
    #[serde(rename = "Question")]
    pub questions: Vec<DnsQuestion>,
    #[serde(rename = "Answer")]
    pub answers: Option<Vec<DnsAnswer>>,
}

#[derive(Deserialize, Debug)]
pub struct DnsQuestion {
    pub name: String,
    pub r#type: i32,
}

#[derive(Deserialize, Debug)]
pub struct DnsAnswer {
    pub name: String,
    pub r#type: i32,
    #[serde(rename = "TTL")]
    pub ttl: i32,
    pub data: String,
}
