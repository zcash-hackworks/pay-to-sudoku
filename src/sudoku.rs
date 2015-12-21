// solver for sudoku grids
use std::rc::Rc;
use std::cell::{RefCell,Cell};
use std::collections::HashMap;
use rand::Rng;

#[derive(Clone)]
struct Possible {
    v: Rc<RefCell<Vec<usize>>>
}

impl Possible {
    fn new(dimension: usize) -> Possible {
        Possible {
            v: Rc::new(RefCell::new((1..(dimension+1)).collect()))
        }
    }

    fn filter_candidates(&self, candidates: &mut Vec<usize>) {
        let v = self.v.borrow();
        candidates.retain(|entry| v.contains(entry));
    }

    fn remove(&self, candidate: usize) {
        let mut v = self.v.borrow_mut();

        v.retain(|&entry| entry != candidate);
    }

    fn add(&self, candidate: usize) {
        let mut v = self.v.borrow_mut();

        v.push(candidate);
    }
}

struct SudokuCell {
    num: Cell<Option<usize>>,
    row: Possible,
    col: Possible,
    group: Possible
}

impl SudokuCell {
    fn candidates(&self, dimension: usize) -> Vec<usize> {
        let mut candidates = (1..(dimension+1)).collect();

        self.row.filter_candidates(&mut candidates);
        self.col.filter_candidates(&mut candidates);
        self.group.filter_candidates(&mut candidates);

        candidates
    }

    fn get(&self) -> Option<usize> {
        self.num.get()
    }

    fn set(&self, to: usize) {
        self.row.remove(to);
        self.col.remove(to);
        self.group.remove(to);
        self.num.set(Some(to));
    }

    fn unset(&self) {
        let old = self.num.get().unwrap();
        self.row.add(old);
        self.col.add(old);
        self.group.add(old);
        self.num.set(None);
    }
}

pub struct Sudoku {
    cells: Vec<SudokuCell>,
    dimension: usize
}

impl Sudoku {
    pub fn gen(n: usize) -> Vec<usize> {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let mut grid = Sudoku::new(n);
        grid.solve(&mut rng);
        grid.clearsome(&mut rng);
        grid.export()
    }

    pub fn import_and_solve(n: usize, puzzle: &[usize]) -> Option<Vec<usize>> {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let mut grid = Sudoku::new(n);
        grid.inject(puzzle);
        match grid.solve(&mut rng) {
            Ok(_) => {
                Some(grid.export())
            },
            _ => None
        }
    }

    pub fn new(n: usize) -> Sudoku {
        let dimension = n * n;

        let rows: Vec<Possible> = (0..dimension).map(|_| Possible::new(dimension)).collect();
        let cols: Vec<Possible> = (0..dimension).map(|_| Possible::new(dimension)).collect();

        let mut groups = HashMap::new();
        for x in 0..n {
            for y in 0..n {
                groups.insert((x, y), Possible::new(dimension));
            }
        }

        let mut grid = Vec::with_capacity(dimension * dimension);

        for y in 0..dimension {
            for x in 0..dimension {
                grid.push(SudokuCell {
                    num: Cell::new(None),
                    row: rows[x].clone(),
                    col: cols[y].clone(),
                    group: groups[&(x / n, y / n)].clone()
                })
            }
        }

        Sudoku {
            cells: grid,
            dimension: dimension
        }
    }

    pub fn inject(&self, other: &[usize]) {
        for (i, &to) in other.iter().enumerate() {
            if to != 0 {
                self.cells[i].set(to);
            }
        }
    }

    pub fn export(&self) -> Vec<usize> {
        let mut acc = vec![];

        for i in 0..(self.dimension * self.dimension) {
            match self.cells[i].get() {
                Some(val) => {
                    acc.push(val);
                },
                None => {
                    acc.push(0);
                }
            }
        }

        acc
    }

    pub fn print(&self) {
        for y in 0..self.dimension {
            for x in 0..self.dimension {
                let val = self.cells[y * self.dimension + x].get();

                match val {
                    Some(val) => {
                        print!("{} ", val);
                    },
                    None => {
                        print!("0 ");
                    }
                }
            }
            println!("");
        }
    }

    pub fn solve<R: Rng>(&self, rng: &mut R) -> Result<(), ()> {
        // Insert into the smallest cell.
        let mut best = None;
        let mut best_n = self.dimension + 1;
        let mut completed = true;

        let it = self.cells.iter();

        for cell in it {
            if cell.get().is_none() {
                completed = false;

                let candidates = cell.candidates(self.dimension);

                if candidates.len() == 0 {
                    // no candidates yet this hasn't been filled?
                    // unsolveable
                    return Err(());
                }

                if candidates.len() < best_n {
                    best_n = candidates.len();

                    best = Some((cell, candidates));
                }
            }
        }

        if completed {
            Ok(())
        } else {
            let (cell, mut candidates) = best.unwrap();

            rng.shuffle(&mut candidates);

            for candidate in candidates {
                let undo = cell.set(candidate);

                if self.solve(rng).is_ok() {
                    return Ok(())
                }

                cell.unset();
            }

            // couldn't solve it apparently
            Err(())
        }
    }

    pub fn clearsome<R: Rng>(&mut self, rng: &mut R) {
        for i in 0..(self.dimension * self.dimension) {
            if rng.gen_weighted_bool(2) {
                self.cells[i].unset();
            }
        }
    }
}

mod test {
    use super::Sudoku;
    use test::Bencher;

    #[bench]
    fn bench_solving(b: &mut Bencher) {
        b.iter(|| {
            let puzzle = Sudoku::gen(3);
            let solution = Sudoku::import_and_solve(3, &puzzle);
        });
    }
}