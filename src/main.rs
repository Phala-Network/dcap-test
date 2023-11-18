use std::ffi::CStr;
use std::time;

use anyhow::anyhow;
use intel_tee_quote_verification_rs as qvl;
use intel_tee_quote_verification_rs::QuoteCollateral as QVLQuoteCollateral;
use intel_tee_quote_verification_sys as qvl_sys;
use scale_codec::Decode;

mod parse_quote;

#[derive(Debug, Clone)]
pub struct QuoteCollateral {
    pub pck_crl_issuer_chain: Vec<u8>,
    pub root_ca_crl: Vec<u8>,
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: Vec<u8>,
    pub tcb_info: Vec<u8>,
    pub qe_identity_issuer_chain: Vec<u8>,
    pub qe_identity: Vec<u8>,
}

impl From<QuoteCollateral> for qvl::QuoteCollateral {
    fn from(value: QuoteCollateral) -> Self {
        fn to_vec_char(value: Vec<u8>) -> Vec<i8> {
            let mut vec: Vec<i8> = value.into_iter().map(|x| x as i8).collect::<Vec<i8>>();
            vec.push(0);
            vec
        }
        qvl::QuoteCollateral {
            major_version: 3,
            minor_version: 0,
            tee_type: 0,
            pck_crl_issuer_chain: to_vec_char(value.pck_crl_issuer_chain),
            root_ca_crl: to_vec_char(value.root_ca_crl),
            pck_crl: to_vec_char(value.pck_crl),
            tcb_info_issuer_chain: to_vec_char(value.tcb_info_issuer_chain),
            tcb_info: to_vec_char(value.tcb_info),
            qe_identity_issuer_chain: to_vec_char(value.qe_identity_issuer_chain),
            qe_identity: to_vec_char(value.qe_identity),
        }
    }
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

async fn get_collateral(base_url: &str, mut quote: &[u8]) -> anyhow::Result<QuoteCollateral> {
    let quote = parse_quote::Quote::decode(&mut quote)?;
    let fmspc = hex::encode_upper(quote.fmspc()?);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
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
    let tcb_info;
    {
        let resposne = client
            .get(format!("{base_url}/tcb?fmspc={fmspc}"))
            .send()
            .await?;
        tcb_info_issuer_chain = get_header(&resposne, "SGX-TCB-Info-Issuer-Chain")
            .or(get_header(&resposne, "TCB-Info-Issuer-Chain"))?;
        tcb_info = resposne.text().await?;
    };
    let qe_identity_issuer_chain;
    let qe_identity;
    {
        let response = client.get(format!("{base_url}/qe/identity")).send().await?;
        qe_identity_issuer_chain = get_header(&response, "SGX-Enclave-Identity-Issuer-Chain")?;
        qe_identity = response.text().await?;
    };
    Ok(QuoteCollateral {
        pck_crl_issuer_chain: pck_crl_issuer_chain.into_bytes(),
        root_ca_crl: root_ca_crl.into_bytes(),
        pck_crl: pck_crl.into_bytes(),
        tcb_info_issuer_chain: tcb_info_issuer_chain.into_bytes(),
        tcb_info: tcb_info.into_bytes(),
        qe_identity_issuer_chain: qe_identity_issuer_chain.into_bytes(),
        qe_identity: qe_identity.into_bytes(),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Generating DCAP quote...");

    let quote = include_bytes!("../res/quote").to_vec();

    // println!("Quote hex:");
    // println!("0x{}", hex::encode(&quote));

    println!("Fetching DCAP quote collateral...");

    let qvl_quote_collateral: qvl::QuoteCollateral =
        get_collateral("https://localhost:8081/sgx/certification/v4/", &quote)
            .await?
            .into();
    // let qvl_quote_collateral = qvl::tee_qv_get_collateral(&quote).unwrap();

    let major_version = qvl_quote_collateral.major_version;
    let minor_version = qvl_quote_collateral.minor_version;
    println!("Collateral Version:");
    println!("{}.{}", major_version, minor_version);

    let tee_type = qvl_quote_collateral.tee_type;
    println!("Collateral TEE type:");
    println!("{}", tee_type);

    let pck_crl_issuer_chain = {
        let c_str: &CStr =
            unsafe { CStr::from_ptr(qvl_quote_collateral.pck_crl_issuer_chain.as_ptr()) };
        let str_slice: &str = c_str
            .to_str()
            .expect("Collateral PCK CRL issuer chain should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("Collateral PCK CRL issuer chain size:");
    println!("{}", qvl_quote_collateral.pck_crl_issuer_chain.len());
    println!("Collateral PCK CRL issuer chain data:");
    println!("{}", pck_crl_issuer_chain);

    let root_ca_crl = {
        let c_str: &CStr = unsafe { CStr::from_ptr(qvl_quote_collateral.root_ca_crl.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("ROOT CA CRL should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("Collateral ROOT CA CRL size:");
    println!("{}", qvl_quote_collateral.root_ca_crl.len());
    println!("Collateral ROOT CA CRL data:");
    println!("0x{}", hex::encode(&root_ca_crl));

    let pck_crl = {
        let c_str: &CStr = unsafe { CStr::from_ptr(qvl_quote_collateral.pck_crl.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("PCK CRL should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("Collateral PCK CRL size:");
    println!("{}", qvl_quote_collateral.pck_crl.len());
    println!("Collateral PCK CRL data:");
    println!("0x{}", hex::encode(&pck_crl));

    let tcb_info_issuer_chain = {
        let c_str: &CStr =
            unsafe { CStr::from_ptr(qvl_quote_collateral.tcb_info_issuer_chain.as_ptr()) };
        let str_slice: &str = c_str
            .to_str()
            .expect("TCB Info issuer should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("Collateral TCB info issuer chain size:");
    println!("{}", qvl_quote_collateral.tcb_info_issuer_chain.len());
    println!("Collateral TCB info issuer chain data:");
    println!("{}", tcb_info_issuer_chain);

    let raw_tcb_info = {
        let c_str: &CStr = unsafe { CStr::from_ptr(qvl_quote_collateral.tcb_info.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("TCB Info should an UTF-8 string");
        str_slice.to_owned()
    };
    let tcb_info_json: serde_json::Value =
        serde_json::from_str(raw_tcb_info.as_str()).expect("TCB Info should a JSON");
    let tcb_info = tcb_info_json["tcbInfo"].to_string();
    let tcb_info_signature = tcb_info_json["signature"]
        .as_str()
        .expect("TCB Info signature should a hex string");
    let tcb_info_signature =
        hex::decode(tcb_info_signature).expect("TCB Info signature should a hex string");
    println!("Collateral TCB info size:");
    println!("{}", qvl_quote_collateral.tcb_info.len());
    println!("Collateral TCB info data:");
    println!("{}", raw_tcb_info);
    println!("{tcb_info}");
    println!("{}", hex::encode(&tcb_info_signature));

    let qe_identity_issuer_chain = {
        let c_str: &CStr =
            unsafe { CStr::from_ptr(qvl_quote_collateral.qe_identity_issuer_chain.as_ptr()) };
        let str_slice: &str = c_str
            .to_str()
            .expect("QE Identity issuer chain should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("Collateral QE identity issuer chain size:");
    println!("{}", qvl_quote_collateral.qe_identity_issuer_chain.len());
    println!("Collateral QE identity issuer chain data:");
    println!("{}", qe_identity_issuer_chain);

    let raw_qe_identity = {
        let c_str: &CStr = unsafe { CStr::from_ptr(qvl_quote_collateral.qe_identity.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("QE Identity should an UTF-8 string");
        str_slice.to_owned()
    };
    let qe_identity_json: serde_json::Value =
        serde_json::from_str(raw_qe_identity.as_str()).expect("QE Identity should a JSON");
    let qe_identity = qe_identity_json["enclaveIdentity"].to_string();
    let qe_identity_signature = qe_identity_json["signature"]
        .as_str()
        .expect("QE Identity signature should a hex string");
    let qe_identity_signature =
        hex::decode(qe_identity_signature).expect("QE Identity signature should a hex string");
    println!("Collateral QE Identity size:");
    println!("{}", qvl_quote_collateral.qe_identity.len());
    println!("Collateral QE identity data:");
    println!("{}", raw_qe_identity);
    println!("{qe_identity}");
    println!("{}", hex::encode(&qe_identity_signature));

    println!("Verifying quote using Intel Quote Verification Library...");
    qvl_quote_verification(&quote, &qvl_quote_collateral);
    println!("Test finished");
    Ok(())
}

pub fn qvl_quote_verification(quote: &[u8], quote_collateral: &QVLQuoteCollateral) {
    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time: u64 = time::SystemTime::now()
        .duration_since(time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    let mut quote_verification_result = qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
    let mut collateral_expiration_status = 1u32;

    match qvl::tee_verify_quote(
        &quote,
        Some(quote_collateral),
        current_time as i64,
        None,
        None,
    ) {
        Ok((colla_exp_stat, qv_result)) => {
            collateral_expiration_status = colla_exp_stat;
            quote_verification_result = qv_result;
            println!("Info: `tee_verify_quote` successfully returned.");
        }
        Err(e) => println!("Info: `tee_verify_quote` failed: {:#04x}", e as u32),
    }
    // check verification result

    let result_status =
        match quote_verification_result {
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
                // The Quote verification passed and is at the latest TCB level
                "OK"
            },
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED => {
                // The Quote verification passed and the platform is patched to
                // the latest TCB level but additional configuration of the SGX
                // platform may be needed
                "CONFIG_NEEDED"
            },
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE => {
                // The Quote is good but TCB level of the platform is out of date.
                // The platform needs patching to be at the latest TCB level
                "OUT_OF_DATE"
            },
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED => {
                // The Quote is good but the TCB level of the platform is out of date
                // and additional configuration of the SGX Platform at its
                // current patching level may be needed. The platform needs
                // patching to be at the latest TCB level
                "OUT_OF_DATE_CONFIG_NEEDED"
            },
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED => {
                // The TCB level of the platform is up to date, but SGX SW Hardening
                "SW_HARDENING_NEEDED"
            },
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
                // The TCB level of the platform is up to date, but additional
                // configuration of the platform at its current patching level
                // may be needed. Moreover, SGX SW Hardening is also needed
                "CONFIG_AND_SW_HARDENING_NEEDED"
            },
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE => {
                // The signature over the application report is invalid
                "INVALID_SIGNATURE"
            },
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED => {
                // The attestation key or platform has been revoked
                "REVOKED"
            },
            qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED => {
                // The Quote verification failed due to an error in one of the input
                "UNSPECIFIED"
            },
            _ => {
                "UNEXPECTED"
            }
        };

    match quote_verification_result {
        qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            if collateral_expiration_status == 0 {
                println!("Verification completed successfully.");
            } else {
                println!("Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            println!("Verification completed with Non-terminal result: {}", result_status);
        }
        qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED
        | _ => {
            println!("Verification completed with Terminal result: {}", result_status);
        }
    }
}
