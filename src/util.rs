use std::io::{self, Read, Write};
use whiteread::{self,parse_line};

pub fn print_sudoku(dim: usize, grid: &[u8]) {
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

pub fn prompt<T: whiteread::White>(prompt: &str) -> T {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    parse_line().unwrap()
}

pub fn get_sudoku_from_stdin(dimension: usize) -> Vec<u8> {
    let mut acc = Vec::with_capacity(dimension*dimension);

    for _ in 0..dimension {
        let v: Vec<u8> = parse_line().unwrap();

        acc.extend(v.into_iter());
    }

    acc
}