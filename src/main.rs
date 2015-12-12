extern crate whiteread;
extern crate rand;
extern crate fixedbitset;
extern crate libc;

mod ffi;

use std::cell::Cell;
use std::iter;
use std::io;
use std::io::Write;
use whiteread::parse_line;

fn prompt<T: whiteread::White>(prompt: &str) -> T {
    print!("{}", prompt);
    io::stdout().flush();
    parse_line().unwrap()
}

fn get_sodoku_from_stdin(mut dimension: usize) -> Vec<u8> {
    let mut acc = Vec::with_capacity(dimension*dimension);

    for _ in 0..dimension {
        let v: Vec<u8> = parse_line().unwrap();

        acc.extend(v.into_iter());
    }

    acc
}

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
*/

fn main() {
    unsafe { ffi::mysnark_init_public_params(); }

    //let n: usize = prompt("N: ");
    let n = 3;
    let dimension = n*n;

    //println!("Specify a puzzle:");

    //let puzzle = get_sodoku_from_stdin(dimension);
    let puzzle = vec![8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 6, 0, 0, 0, 0, 0, 0, 7, 0, 0, 9, 0, 2, 0, 0, 0, 5, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 5, 7, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 6, 8, 0, 0, 8, 5, 0, 0, 0, 1, 0, 0, 9, 0, 0, 0, 0, 4, 0, 0];
    let mut solution = vec![
            8, 1, 2, 7, 5, 3, 6, 4, 9,
            9, 4, 3, 6, 8, 2, 1, 7, 5,
            6, 7, 5, 4, 9, 1, 2, 8, 3,
            
            1, 5, 4, 2, 3, 7, 8, 9, 6,
            3, 6, 9, 8, 4, 5, 7, 2, 1,
            2, 8, 7, 1, 6, 9, 5, 3, 4,

            5, 2, 1, 9, 7, 4, 3, 6, 8,
            4, 3, 8, 5, 2, 6, 9, 1, 7,
            7, 9, 6, 3, 1, 8, 4, 5, 2];

    let mut key = vec![206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94];
    let h_of_key = vec![253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164, 65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9];

    ffi::generate_keypair(3, |pk, vk| {
        println!("good for you");
        let ctx = ffi::get_context(pk, vk, 3);

        println!("nice");

        assert!(ffi::prove(ctx, &puzzle, &solution, &key, &h_of_key, |e, p| {
            println!("proof len: {}", p.len());
            println!("enc solution len: {}", e.len());

            let mut d: Vec<u8> = e.into();

            ffi::decrypt(ctx, &mut d, &key);

            assert_eq!(d, solution);
        }));

        key[0] = 0;

        assert!(!ffi::prove(ctx, &puzzle, &solution, &key, &h_of_key, |_, _| {
            
        }));

        key[0] = 206;

        solution[0] = 9;

        assert!(!ffi::prove(ctx, &puzzle, &solution, &key, &h_of_key, |_, _| {
            
        }));

        println!("ok");
    });
}
