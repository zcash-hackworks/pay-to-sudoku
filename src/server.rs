/*
sample puzzle:

8 0 0 0 0 0 0 0 0
0 0 3 6 0 0 0 0 0
0 7 0 0 9 0 2 0 0
0 5 0 0 0 7 0 0 0
0 0 0 0 4 5 7 0 0
0 0 0 1 0 0 0 3 0
0 0 1 0 0 0 0 6 8
0 0 8 5 0 0 0 1 0
0 9 0 0 0 0 4 0 0

solution:

8 1 2 7 5 3 6 4 9
9 4 3 6 8 2 1 7 5
6 7 5 4 9 1 2 8 3
1 5 4 2 3 7 8 9 6
3 6 9 8 4 5 7 2 1
2 8 7 1 6 9 5 3 4
5 2 1 9 7 4 3 6 8
4 3 8 5 2 6 9 1 7
7 9 6 3 1 8 4 5 2
*/

extern crate whiteread;
extern crate libc;
extern crate bincode;
extern crate hex;
extern crate serde;

use std::net::{TcpListener,TcpStream};
use std::io::{self, Read, Write};
use self::ffi::*;
use whiteread::parse_line;
use bincode::serde::{serialize_into, deserialize_from};
use bincode::SizeLimit::Infinite;
use serde::bytes::Bytes;
use std::borrow::Cow;
use hex::{ToHex, FromHex};

mod ffi;

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
        println!("Specify a sodoku puzzle! {0} lines with {0} numbers (whitespace delimited).", ctx.n*ctx.n);
        println!("0 represents a blank cell.");
        println!("Go!");

        let puzzle = get_sodoku_from_stdin(ctx.n*ctx.n);

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

fn print_sudoku(dim: usize, grid: &[u8]) {
    for y in 0..dim {
        for x in 0..dim {
            print!("{}", grid[y*dim + x]);
            if x != (dim-1) || y != (dim-1) {
                print!(" ");
            }
        }
        println!("");
    }
    println!("");
}

fn prompt<T: whiteread::White>(prompt: &str) -> T {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    parse_line().unwrap()
}

fn get_sodoku_from_stdin(dimension: usize) -> Vec<u8> {
    let mut acc = Vec::with_capacity(dimension*dimension);

    for _ in 0..dimension {
        let v: Vec<u8> = parse_line().unwrap();

        acc.extend(v.into_iter());
    }

    acc
}