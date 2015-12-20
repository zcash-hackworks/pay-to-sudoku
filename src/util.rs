use std::io::{self, Read, Write};
use whiteread::{self,parse_line};
use std::fs;
use flate2::write::{ZlibEncoder, ZlibDecoder};
use flate2::Compression;

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

pub fn write_compressed(path: &str, data: &[u8]) {
    let handle = fs::File::create(path).unwrap();
    let mut encoder = ZlibEncoder::new(handle, Compression::Best);
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap();
}

pub fn decompress(path: &str) -> Vec<u8> {
    let mut result = Vec::new();

    {
        let mut decoder = ZlibDecoder::new(&mut result);
        let mut handle = fs::File::open(path).unwrap();

        loop {
            let mut buf = [0; 1024];

            let read = handle.read(&mut buf).unwrap();
            if read == 0 {
                decoder.finish();
                break;
            }

            decoder.write_all(&buf[0..read]).unwrap();
        }
    }

    result
}