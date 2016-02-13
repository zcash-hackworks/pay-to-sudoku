use serde;
use jsonrpc;
use strason::Json;

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