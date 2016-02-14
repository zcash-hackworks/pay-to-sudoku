// non-existent error handling and manual parsing
// of the serialized results, not exactly a model
// for others

use serde;
use jsonrpc;
use strason::Json;
use hex::{ToHex, FromHex};
use crypto::sha2::Sha256;
use crypto::digest::Digest;

pub fn get_preimage(client: &mut jsonrpc::client::Client, image: &[u8])
-> Option<Vec<u8>>
{
    // import the preimage
    let request = client.build_request("listtransactions".to_string(), vec!["*".into(), 10.into(), 0.into(), true.into()]);
    let res = client.send_request(&request).unwrap().result.unwrap();
    let res = res.array().unwrap();

    for tx in res {
        let tx = tx.object().unwrap();

        for &(ref field, ref value) in tx {
            if field == "preimage" {
                let preimage = Vec::<u8>::from_hex(value.string().unwrap()).unwrap();
                let mut image_compare: Vec<u8> = (0..32).map(|_| 0).collect();

                let mut hash = Sha256::new();
                hash.input(&preimage);
                hash.result(&mut image_compare);

                if &*image_compare == image {
                    return Some(preimage);
                }
            }
        }
    }

    None
}

pub fn solve_sudoku(client: &mut jsonrpc::client::Client,
                    key: &str,
                    txid: &str,
                    vout: usize
                   ) -> String
{
    // import the preimage
    let request = client.build_request("importpreimage".to_string(), vec![key.into()]);
    let res = client.send_request(&request).unwrap();

    // get receive address
    let request = client.build_request("getnewaddress".to_string(), vec![]);

    match client.send_request(&request).and_then(|res| res.into_result::<String>()) {
        Ok(addr) => {
            let request = client.build_request("createrawtransaction".to_string(), vec![
                Json::from_str(&format!("[{{\"txid\":\"{}\",\"vout\":{}}}]", txid, vout)).expect("parsing inputs"),
                Json::from_str(&format!("{{\"{}\":0.09}}", addr)).expect("parsing outputs")
            ]);
            match client.send_request(&request).and_then(|res| res.into_result::<String>()) {
                Ok(tx) => {
                    let request = client.build_request("signrawtransaction".to_string(), vec![tx.into()]);
                    let res = client.send_request(&request).unwrap().result.unwrap();

                    let res = res.object().unwrap();

                    let mut signed_tx: Option<&str> = None;
                    let mut complete = false;

                    for &(ref field, ref value) in res {
                        if field == "hex" {
                            signed_tx = value.string();
                        } else if field == "complete" {
                            complete = value.bool().unwrap();
                        }
                    }

                    assert_eq!(complete, true);

                    let signed_tx = signed_tx.unwrap();

                    let request = client.build_request("sendrawtransaction".to_string(), vec![signed_tx.into()]);
                    let res: String = client.send_request(&request).unwrap().into_result::<String>().unwrap();

                    //println!("sent signed raw tx: {}", signed_tx);
                    //println!("txid: {}", res);

                    res
                },
                Err(e) => panic!("error constructing transaction {:?}", e)
            }
        },
        Err(e) => panic!("error getting new address {:?}", e)
    }
}

pub fn poll_for_payment(client: &mut jsonrpc::client::Client,
                        p2sh: &str
) -> Option<(String, usize)>
{
    let request = client.build_request("listtransactions".to_string(), vec!["*".into(), 100.into(), 0.into(), true.into()]);
    let res = client.send_request(&request).unwrap().result.unwrap();
    let res = res.array().unwrap();

    for tx in res {
        let tx = tx.object().unwrap();
        let mut found = false;
        let mut confirmations = 0;
        let mut txid = None;
        let mut vout = None;

        for &(ref field, ref value) in tx {
            if field == "address" {
                if value.string().unwrap() == p2sh {
                    found = true;
                }
            } else if field == "txid" {
                txid = value.string();
            } else if field == "vout" {
                vout = value.num();
            } else if field == "confirmations" {
                confirmations = value.num().unwrap().parse().unwrap();
            }
        }

        if found && confirmations > 0 {
            return Some((txid.unwrap().into(), vout.unwrap().parse().unwrap()));
        }
    }

    None
}

pub fn pay_for_sudoku(client: &mut jsonrpc::client::Client,
                      p2sh: &str)
{
    let request = client.build_request("sendtoaddress".to_string(), vec![p2sh.into(), "0.1".into()]);
    let res = client.send_request(&request).unwrap();
}

pub fn p2sh(client: &mut jsonrpc::client::Client,
            solving_pubkey: &str,
            refund_pubkey: &str,
            image: &str,
            cltv_height: usize
           ) -> String
{
    let request = client.build_request("zkcpscript".to_string(), vec![solving_pubkey.into(), refund_pubkey.into(), image.into(), cltv_height.into()]);
    let res = client.send_request(&request).unwrap().result.unwrap();
    let res = res.object().unwrap();

    let mut redeem_script = None;
    let mut p2sh = None;

    for i in res {
        if &*i.0 == "redeem_script" {
            redeem_script = (i.1).string()
        }
        if &*i.0 == "p2sh" {
            p2sh = (i.1).string()
        }
    }

    let redeem_script = redeem_script.unwrap();
    let p2sh = p2sh.unwrap();

    println!("Importing address into wallet for redeem script: {}", redeem_script);
    println!("\tP2SH Address: {}", p2sh);

    let request = client.build_request("importaddress".to_string(), vec![redeem_script.into(), "".into(), false.into(), true.into()]);
    let res = client.send_request(&request).unwrap();

    p2sh.into()
}

pub fn getheight(client: &mut jsonrpc::client::Client) -> usize {
    let request = client.build_request("getinfo".to_string(), vec![]);
    let res = client.send_request(&request).unwrap().result.unwrap();
    let res = res.object().unwrap();

    for i in res {
        if &*i.0 == "blocks" {
            return (i.1).num().unwrap().parse().unwrap()
        }
    }

    panic!("couldn't get height")
}

pub fn getpubkey(client: &mut jsonrpc::client::Client) -> String {
    let request = client.build_request("getnewaddress".to_string(), vec![]);

    match client.send_request(&request).and_then(|res| res.into_result::<String>()) {
        Ok(string) => {
            let request = client.build_request("validateaddress".to_string(), vec![string.into()]);

            let res = client.send_request(&request).unwrap().result.unwrap();
            let res = res.object().unwrap();

            for i in res {
                if &*i.0 == "pubkey" {
                    return (i.1).string().unwrap().into();
                }
            }

            panic!("validateaddress didn't return a pubkey field?");
        },
        Err(e) => {
            panic!("getnewaddress failed: {:?}", e)
        }
    }
}