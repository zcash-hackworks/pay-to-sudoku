extern crate whiteread;
extern crate libc;
extern crate bincode;
extern crate rand;
extern crate hex;
extern crate serde;
extern crate clap;
extern crate flate2;

use std::net::{TcpListener,TcpStream};
use std::io::{self, Read, Write};
use self::ffi::*;
use self::sudoku::Sudoku;
use self::util::*;
use whiteread::parse_line;
use bincode::serde::{serialize_into, deserialize_from};
use bincode::SizeLimit::Infinite;
use serde::bytes::Bytes;
use std::borrow::Cow;
use hex::{ToHex, FromHex};
use clap::{App, Arg, SubCommand};

mod sudoku;
mod ffi;
mod util;

fn is_number(val: String) -> Result<(), String> {
    let n = val.parse::<usize>();

    match n {
        Err(_) => Err("`n` must be a number".into()),
        Ok(n) => {
            if n == 0 || n > 9 {
                Err("0 < n < n".into())
            } else {
                Ok(())
            }
        }
    }
}

fn main() {
    initialize();

    let matches = App::new("pay-to-sudoku")
                  .subcommand(SubCommand::with_name("gen")
                              .about("Generates a proving/verifying zkSNARK keypair")
                              .arg(Arg::with_name("n")
                                   .required(true)
                                   .validator(is_number))
                  )
                  .subcommand(SubCommand::with_name("test")
                              .about("Creates, solves, proves and verifies")
                              .arg(Arg::with_name("n")
                                   .required(true)
                                   .validator(is_number))
                   )
                  .get_matches();

    if let Some(ref matches) = matches.subcommand_matches("gen") {
        let n: usize = matches.value_of("n").unwrap().parse().unwrap();

        generate_keypair(n, |pk, vk| {
            println!("Serialized proving key size in bytes: {}", pk.len());
            println!("Serialized verifying key size in bytes: {}", vk.len());

            println!("Storing...");

            write_compressed(&format!("{}.pk", n), &pk);
            write_compressed(&format!("{}.vk", n), &vk);
        });
    }



    if let Some(ref matches) = matches.subcommand_matches("test") {
        println!("Loading proving/verifying keys...");
        let n: usize = matches.value_of("n").unwrap().parse().unwrap();

        let ctx = {
            let pk = decompress(&format!("{}.pk", n));
            let vk = decompress(&format!("{}.vk", n));

            get_context(&pk, &vk, n)
        };

        loop {
            println!("Generating puzzle...");
            let puzzle = Sudoku::gen(n);
            println!("Solving puzzle...");
            let solution = Sudoku::import_and_solve(n, &puzzle).unwrap();

            let puzzle: Vec<u8> = puzzle.into_iter().map(|x| x as u8).collect();
            let solution: Vec<u8> = solution.into_iter().map(|x| x as u8).collect();

            let key = vec![206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94];
            let h_of_key = vec![253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164, 65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9];

            println!("Generating proof...");

            assert!(prove(ctx, &puzzle, &solution, &key, &h_of_key,
              |encrypted_solution, proof| {}));
        }
    }
}

/*
fn main() {
    initialize();

    println!("You're the 'server', you pick the puzzle and pay for the solution.");
    println!("Puzzle is of size N^2 by N^2 with N by N groups.");
    println!("An N of 3 will produce a traditional 9x9 sudoku.");

    let n: usize = prompt("N: ");

    println!("Generating proving/verifying keys for the snark...");

    generate_keypair(n, |pk, vk| {
        println!("Constructing context from keys...");

        let ctx = get_context(pk, vk, n);

        let listener = TcpListener::bind("0.0.0.0:9876").unwrap();

        println!("Opened listener. Instruct client to connect.");

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    handle_client(&mut stream, ctx, pk, vk);
                },
                Err(_) => {}
            }
        }
    });
}

fn handle_client(stream: &mut TcpStream, ctx: Context, pk: &[i8], vk: &[i8]) {
    {
        println!("Sending proving/verifying keys over the network...");
        let pk = Cow::Borrowed(pk);
        let vk = Cow::Borrowed(vk);

        serialize_into(stream, &ctx.n, Infinite);
        serialize_into(stream, &pk, Infinite);
        serialize_into(stream, &vk, Infinite);
    }

    loop {
        println!("Specify a sudoku puzzle! {0} lines with {0} numbers (whitespace delimited).", ctx.n*ctx.n);
        println!("0 represents a blank cell.");
        println!("Go!");

        let puzzle = get_sudoku_from_stdin(ctx.n*ctx.n);

        println!("Sending puzzle over the network...");

        serialize_into(stream, &puzzle, Infinite);

        println!("Receiving proof of solution...");

        let proof: Cow<[i8]> = deserialize_from(stream, Infinite).unwrap();
        let encrypted_solution: Cow<[u8]> = deserialize_from(stream, Infinite).unwrap();
        let h_of_key: Vec<u8> = deserialize_from(stream, Infinite).unwrap();
        
        if verify(ctx, &proof, &puzzle, &h_of_key, &encrypted_solution) {
            println!("Proof is valid!");
            println!("In order to decrypt the proof, get the preimage of {}", h_of_key.to_hex());

            let key: String = prompt("Preimage: ");
            let key: Vec<u8> = FromHex::from_hex(&key).unwrap();

            let mut encrypted_solution = encrypted_solution.into_owned();

            decrypt(ctx, &mut encrypted_solution, &key);

            print_sudoku(ctx.n*ctx.n, &encrypted_solution);
        } else {
            println!("The remote end provided a proof that wasn't valid!");
        }
    }
}
*/