use core::time::Duration;

use anyhow::{anyhow, Result};
use scale_codec::{Encode, Decode};
use scale_info::TypeInfo;

mod parse_quote;

#[derive(Encode, Decode, TypeInfo, Clone, PartialEq, Eq, Debug)]
pub struct SgxV30QuoteCollateral {
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub qe_identity_signature: Vec<u8>,
}

fn get_header(response: &reqwest::Response, name: &str) -> anyhow::Result<String> {
    let value = response
        .headers()
        .get(name)
        .ok_or(anyhow!("Missing {name}"))?
        .to_str()?;
    let value = urlencoding::decode(value)?;
    Ok(value.into_owned())
}

/// Get collateral given DCAP quote and base URL of PCCS server URL.
pub async fn get_collateral(
    pccs_url: &str,
    mut quote: &[u8],
    timeout: Duration
) -> Result<SgxV30QuoteCollateral> {
    let quote = parse_quote::Quote::decode(&mut quote)?;
    let fmspc = hex::encode_upper(quote.fmspc()?);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(timeout)
        .build()?;
    let base_url = pccs_url.trim_end_matches('/');

    let pck_crl_issuer_chain;
    let pck_crl;
    {
        let response = client
            .get(format!("{base_url}/pckcrl?ca=processor"))
            .send()
            .await?;
        pck_crl_issuer_chain = get_header(&response, "SGX-PCK-CRL-Issuer-Chain")?;
        pck_crl = response.text().await?;
    };
    let root_ca_crl = client
        .get(format!("{base_url}/rootcacrl"))
        .send()
        .await?
        .text()
        .await?;
    let tcb_info_issuer_chain;
    let raw_tcb_info;
    {
        let resposne = client
            .get(format!("{base_url}/tcb?fmspc={fmspc}"))
            .send()
            .await?;
        tcb_info_issuer_chain = get_header(&resposne, "SGX-TCB-Info-Issuer-Chain")
            .or(get_header(&resposne, "TCB-Info-Issuer-Chain"))?;
        raw_tcb_info = resposne.text().await?;
    };
    let qe_identity_issuer_chain;
    let raw_qe_identity;
    {
        let response = client.get(format!("{base_url}/qe/identity")).send().await?;
        qe_identity_issuer_chain = get_header(&response, "SGX-Enclave-Identity-Issuer-Chain")?;
        raw_qe_identity = response.text().await?;
    };

    let tcb_info_json: serde_json::Value = serde_json::from_str(&raw_tcb_info)
        .map_err(|_| anyhow!("TCB Info should a JSON"))?;
    let tcb_info = tcb_info_json["tcbInfo"].to_string();
    let tcb_info_signature = tcb_info_json
        .get("signature")
        .ok_or(anyhow!("TCB Info should has `signature` field"))?
        .as_str()
        .ok_or(anyhow!("TCB Info signature should a hex string"))?;
    let tcb_info_signature = hex::decode(tcb_info_signature)
        .map_err(|_| anyhow!("TCB Info signature should a hex string"))?;

    let qe_identity_json: serde_json::Value = serde_json::from_str(raw_qe_identity.as_str())
        .map_err(|_| anyhow!("QE Identity should a JSON"))?;
    let qe_identity = qe_identity_json
        .get("enclaveIdentity")
        .ok_or(anyhow!("QE Identity should has `enclaveIdentity` field"))?
        .to_string();
    let qe_identity_signature = qe_identity_json.get("signature")
        .ok_or(anyhow!("QE Identity should has `signature` field"))?
        .as_str()
        .ok_or(anyhow!("QE Identity signature should a hex string"))?;
    let qe_identity_signature = hex::decode(qe_identity_signature)
        .map_err(|_| anyhow!("QE Identity signature should a hex string"))?;

    Ok(SgxV30QuoteCollateral {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pccs_host = std::env::var("PCCS_HOST").unwrap_or("https://localhost:8081".to_owned());
    let pccs_endpoint = format!("{pccs_host}/sgx/certification/v4/");
    let timeout = Duration::from_secs(30);

    println!("Generating DCAP quote...");

    let quote = include_bytes!("../res/quote").to_vec();

    // println!("Quote hex:");
    // println!("0x{}", hex::encode(&quote));

    println!("Fetching DCAP quote collateral...");

    let quote_collateral =
        get_collateral(&pccs_endpoint, &quote, timeout).await?;
    // let qvl_quote_collateral = qvl::tee_qv_get_collateral(&quote).unwrap();

    println!("Collateral PCK CRL issuer chain:");
    println!("{}", &quote_collateral.pck_crl_issuer_chain);

    println!("Collateral ROOT CA CRL:");
    println!("0x{}", &quote_collateral.root_ca_crl);

    println!("Collateral PCK CRL:");
    println!("0x{}", &quote_collateral.pck_crl);

    println!("Collateral TCB info issuer chain:");
    println!("{}", &quote_collateral.tcb_info_issuer_chain);

    println!("Collateral TCB info:");
    println!("{}", &quote_collateral.tcb_info);
    println!("Collateral TCB info signature:");
    println!("{}", hex::encode(&quote_collateral.tcb_info_signature));

    println!("Collateral QE identity issuer chain:");
    println!("{}", &quote_collateral.qe_identity_issuer_chain);

    println!("Collateral QE Identity info:");
    println!("{}", &quote_collateral.qe_identity);
    println!("Collateral QE Identity signature:");
    println!("{}", hex::encode(&quote_collateral.qe_identity_signature));

    std::fs::create_dir_all("data/storage_files/quote_collateral_artifacts")?;
    std::fs::write(
        "data/storage_files/quote_collateral_artifacts/pck_crl_issuer_chain",
        &quote_collateral.pck_crl_issuer_chain
    ).unwrap();
    std::fs::write(
        "data/storage_files/quote_collateral_artifacts/root_ca_crl",
        &quote_collateral.root_ca_crl
    ).unwrap();
    std::fs::write(
        "data/storage_files/quote_collateral_artifacts/pck_crl",
        &quote_collateral.pck_crl
    ).unwrap();
    std::fs::write(
        "data/storage_files/quote_collateral_artifacts/tcb_info_issuer_chain",
        &quote_collateral.tcb_info_issuer_chain
    ).unwrap();
    std::fs::write(
        "data/storage_files/quote_collateral_artifacts/tcb_info",
        &quote_collateral.tcb_info
    ).unwrap();
    std::fs::write(
        "data/storage_files/quote_collateral_artifacts/qe_identity_issuer_chain",
        &quote_collateral.qe_identity_issuer_chain
    ).unwrap();
    std::fs::write(
        "data/storage_files/quote_collateral_artifacts/qe_identity",
        &quote_collateral.qe_identity
    ).unwrap();

    let encoded = quote_collateral.encode();
    // println!("0x{}", hex::encode(&encoded));

    std::fs::write(
        "data/storage_files/quote_collateral",
        &encoded
    ).unwrap();

    std::fs::write(
        "data/storage_files/quote",
        &quote
    ).unwrap();

    Ok(())
}
