extern crate whiteread;
extern crate libc;
extern crate bincode;
extern crate serde;

use std::net::{TcpListener,TcpStream};
use std::io::{self, Read, Write, BufReader};
use self::ffi::*;
use whiteread::parse_line;
use bincode::serde::{serialize_into, deserialize_from};
use bincode::SizeLimit::Infinite;
use serde::bytes::Bytes;
use std::borrow::Cow;

mod ffi;

fn main() {
    initialize();

    let host: String = prompt("Enter remote host/IP: ");

    let mut stream = TcpStream::connect(&*host).unwrap();
    //let mut stream = BufReader::new(stream);

    println!("Receiving proving/verifying keys from server...");

    let n: usize = deserialize_from(&mut stream, Infinite).unwrap();
    let pk: Cow<[i8]> = deserialize_from(&mut stream, Infinite).unwrap();
    let vk: Cow<[i8]> = deserialize_from(&mut stream, Infinite).unwrap();

    println!("Constructing context...");

    let ctx = get_context(&pk, &vk, n);

    loop {
        println!("Waiting for server to give us a puzzle...");
        let puzzle: Vec<u8> = deserialize_from(&mut stream, Infinite).unwrap();

        println!("Solve it and post the solution.");
        let solution = get_sodoku_from_stdin(ctx.n*ctx.n);

        let key = vec![206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94];
        let h_of_key = vec![253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164, 65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9];

        assert_eq!(ffi::prove(ctx,
                              &puzzle,
                              &solution,
                              &key,
                              &h_of_key, |encrypted_solution, proof| {
            
            let encrypted_solution = Cow::Borrowed(encrypted_solution);
            let proof = Cow::Borrowed(proof);

            serialize_into(&mut stream, &proof, Infinite);
            serialize_into(&mut stream, &encrypted_solution, Infinite);
            serialize_into(&mut stream, &h_of_key, Infinite);
            
        }), true);
    }
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