#![feature(test)]

extern crate whiteread;
extern crate libc;
extern crate bincode;
extern crate rand;
extern crate hex;
extern crate serde;
extern crate clap;
extern crate flate2;
extern crate test;

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
                  .subcommand(SubCommand::with_name("serve")
                              .about("Opens a server for paying people to solve sudoku puzzles")
                              .arg(Arg::with_name("n")
                                   .required(true)
                                   .validator(is_number))
                   )
                  .subcommand(SubCommand::with_name("client")
                              .about("Connects to a server to receive payment to solve sudoku puzzles")
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

    if let Some(ref matches) = matches.subcommand_matches("client") {
        println!("Loading proving/verifying keys...");
        let n: usize = matches.value_of("n").unwrap().parse().unwrap();

        let ctx = {
            println!("\tProving key...");
            let pk = decompress(&format!("{}.pk", n));
            println!("\tVerifying key...");
            let vk = decompress(&format!("{}.vk", n));

            println!("\tDeserializing...");

            get_context(&pk, &vk, n)
        };

        let mut stream = TcpStream::connect("127.0.0.1:25519").unwrap();

        handle_server(&mut stream, &ctx, n);
    }

    if let Some(ref matches) = matches.subcommand_matches("serve") {
        println!("Loading proving/verifying keys...");
        let n: usize = matches.value_of("n").unwrap().parse().unwrap();

        let ctx = {
            println!("\tProving key...");
            let pk = decompress(&format!("{}.pk", n));
            println!("\tVerifying key...");
            let vk = decompress(&format!("{}.vk", n));

            println!("\tDeserializing...");

            get_context(&pk, &vk, n)
        };

        let listener = TcpListener::bind("0.0.0.0:25519").unwrap();
        println!("Opened listener. Instruct client to connect.");

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    handle_client(&mut stream, &ctx, n);
                },
                Err(_) => {}
            }
        }
    }

    if let Some(ref matches) = matches.subcommand_matches("test") {
        println!("Loading proving/verifying keys...");
        let n: usize = matches.value_of("n").unwrap().parse().unwrap();

        let ctx = {
            println!("\tProving key...");
            let pk = decompress(&format!("{}.pk", n));
            println!("\tVerifying key...");
            let vk = decompress(&format!("{}.vk", n));

            println!("\tDeserializing...");

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

            assert!(prove(&ctx, &puzzle, &solution, &key, &h_of_key,
              |encrypted_solution, proof| {}));
        }
    }
}

fn handle_client(stream: &mut TcpStream, ctx: &Context, n: usize) -> Result<(), ProtoError> {
    println!("Connected!");

    println!("Generating puzzle...");
    let puzzle = Sudoku::gen(n);

    print_sudoku(n*n, &puzzle);

    println!("Sending to the client.");

    try!(serialize_into(stream, &puzzle, Infinite));

    println!("Waiting for proof that the client has a solution...");

    let proof: Cow<[u8]> = deserialize_from(stream, Infinite).unwrap();
    let encrypted_solution: Cow<[u8]> = deserialize_from(stream, Infinite).unwrap();
    let mut encrypted_solution: Vec<u8> = encrypted_solution.into_owned();
    let mut h_of_key: Vec<u8> = deserialize_from(stream, Infinite).unwrap();

    println!("Verifying proof.");

    if verify(ctx, &proof, &puzzle, &h_of_key, &encrypted_solution) {
        println!("Proof verified!");

        println!("Decrypting the solution with key which we presumably obtain via the bitcoin transaction...");

        let key = vec![206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94];

        decrypt(ctx, &mut encrypted_solution, &key);

        println!("Decrypted solution:");
        print_sudoku(n*n, &encrypted_solution);

        return Ok(());
    }

    println!("Proof invalid!");

    Err(ProtoError)
}

fn handle_server(stream: &mut TcpStream, ctx: &Context, n: usize) -> Result<(), ProtoError> {
    println!("Waiting for server to give us a puzzle...");
    let puzzle: Vec<u8> = deserialize_from(stream, Infinite).unwrap();

    println!("Received puzzle:");
    print_sudoku(n*n, &puzzle);

    println!("Solving puzzle...");
    let solution: Vec<u8> = Sudoku::import_and_solve(n, &puzzle).unwrap();
    print_sudoku(n*n, &solution);

    let key = vec![206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94];
    let h_of_key = vec![253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164, 65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9];

    println!("Generating proof...");

    assert!(prove(ctx, &puzzle, &solution, &key, &h_of_key, |encrypted_solution, proof| {
        println!("Sending proof, encrypted_solution and h_of_key to the server.");

        let encrypted_solution = Cow::Borrowed(encrypted_solution);
        let proof = Cow::Borrowed(proof);

        serialize_into(stream, &proof, Infinite);
        serialize_into(stream, &encrypted_solution, Infinite);
        serialize_into(stream, &h_of_key, Infinite);
    }));

    Ok(())
}

struct ProtoError;

impl From<bincode::serde::SerializeError> for ProtoError {
    fn from(a: bincode::serde::SerializeError) -> ProtoError {
        ProtoError
    }
}
