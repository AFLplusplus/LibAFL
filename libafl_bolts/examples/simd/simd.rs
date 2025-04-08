use chrono::Utc;
use clap::Parser;
use itertools::Itertools;
use libafl_bolts::simd::{
    covmap_is_interesting_naive, covmap_is_interesting_u8x16, covmap_is_interesting_u8x32,
    simplify_map_naive, simplify_map_u8x16, simplify_map_u8x32,
};
use rand::{RngCore, rngs::ThreadRng};

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value_t = 2097152, env = "LIBAFL_BENCH_MAP_SIZE")]
    pub map: usize,
    #[arg(short, long, default_value_t = 32768, env = "LIBAFL_BENCH_ROUNDS")]
    pub rounds: usize,
    #[arg(short, long, env = "LIBAFL_BENCH_CORRECTNESS")]
    pub validate: bool,
    #[arg(short, long)]
    pub bench: bool, // ?? Cargo sends this??
}

fn random_bits(map: &mut [u8], rng: &mut ThreadRng) {
    // randomly set a bit since coverage map is usually sparse enough
    let rng = rng.next_u64() as usize;
    let bytes_idx = (rng / 8) % map.len();
    let bits_idx = rng % 8;
    map[bytes_idx] |= 1 << bits_idx;
}

fn clean_vectors(map: &mut [u8]) {
    for it in map.iter_mut() {
        *it = 0;
    }
}

struct SimplifyMapInput {
    name: String,
    func: fn(&mut [u8]),
    map: Vec<u8>,
    rounds: usize,
    validate: bool,
    rng: ThreadRng,
}

impl SimplifyMapInput {
    fn from_cli(name: &str, f: fn(&mut [u8]), cli: &Cli, rng: &ThreadRng) -> Self {
        Self {
            name: name.to_string(),
            func: f,
            map: vec![0; cli.map],
            rng: rng.clone(),
            rounds: cli.rounds,
            validate: cli.validate,
        }
    }
    fn measure_simplify_input(mut self) -> Vec<chrono::TimeDelta> {
        println!("Running {}", &self.name);
        let mut outs = vec![];
        println!("warm up...");
        for _ in 0..16 {
            (self.func)(&mut self.map);
        }
        clean_vectors(&mut self.map);
        for _ in 0..self.rounds {
            random_bits(&mut self.map, &mut self.rng);
            let before = Utc::now();

            if self.validate {
                let mut mp = self.map.clone();
                (self.func)(&mut self.map);
                simplify_map_naive(&mut mp);

                assert!(
                    mp == self.map,
                    "Incorrect covmap impl. {:?} vs\n{:?}",
                    mp,
                    self.map
                );
            } else {
                (self.func)(&mut self.map);
            }
            let after = Utc::now();
            outs.push(after - before);
        }

        outs
    }
}

type CovFuncPtr = fn(&[u8], &[u8], bool) -> (bool, Vec<usize>);

struct CovInput {
    name: String,
    func: CovFuncPtr,
    hist: Vec<u8>,
    map: Vec<u8>,
    rounds: usize,
    validate: bool,
    rng: ThreadRng,
}

impl CovInput {
    fn from_cli(name: &str, f: CovFuncPtr, cli: &Cli, rng: &ThreadRng) -> Self {
        CovInput {
            name: name.to_string(),
            func: f,
            hist: vec![0; cli.map],
            map: vec![0; cli.map],
            rng: rng.clone(),
            rounds: cli.rounds,
            validate: cli.validate,
        }
    }
    fn measure_cov(mut self) -> Vec<chrono::TimeDelta> {
        println!("Running {}", &self.name);
        let mut outs = vec![];
        println!("warm up...");
        for _ in 0..16 {
            (self.func)(&self.hist, &self.map, true);
        }
        clean_vectors(&mut self.hist);
        clean_vectors(&mut self.map);
        for _ in 0..self.rounds {
            random_bits(&mut self.map, &mut self.rng);
            let before = Utc::now();
            let (interesting, novelties) = (self.func)(&self.hist, &self.map, true);
            if self.validate {
                let (canonical_interesting, canonical_novelties) =
                    covmap_is_interesting_naive(&self.hist, &self.map, true);

                assert!(
                    canonical_interesting == interesting && novelties == canonical_novelties,
                    "Incorrect covmap impl. {canonical_interesting} vs {interesting}, {canonical_novelties:?} vs\n{novelties:?}"
                );
            }
            let after = Utc::now();
            outs.push(after - before);
        }

        outs
    }
}

#[allow(clippy::cast_precision_loss)]
fn printout(ty: &str, tms: &[chrono::TimeDelta]) {
    let tms = tms
        .iter()
        .map(|t| t.to_std().unwrap().as_secs_f64())
        .collect_vec();
    let mean = tms.iter().sum::<f64>() / tms.len() as f64;
    let min = tms.iter().fold(0f64, |acc, x| acc.min(*x));
    let max = tms.iter().fold(0f64, |acc, x| acc.max(*x));
    let std = (tms
        .iter()
        .fold(0f64, |acc, x| acc + (*x - mean) * (*x - mean))
        / (tms.len() - 1) as f64)
        .sqrt();
    let sum: f64 = tms.into_iter().sum();
    println!(
        "{}: avg {:.03}, min {:.03}, max {:.03}, std {:.03}, sum {:.03}",
        ty,
        mean * 1000.0,
        min * 1000.0,
        max * 1000.0,
        std * 1000.0,
        sum * 1000.0
    );
}

fn main() {
    // Bench with `taskset -c 3 cargo bench --example simd`
    // Validate with `cargo bench --example simd -- --validate --rounds 8192`
    let cli = Cli::parse();

    let rng = rand::rng();

    let simpls = [
        SimplifyMapInput::from_cli("naive simplify_map", simplify_map_naive, &cli, &rng),
        SimplifyMapInput::from_cli("u8x16 simplify_map", simplify_map_u8x16, &cli, &rng),
        SimplifyMapInput::from_cli("u8x32 simplify_map", simplify_map_u8x32, &cli, &rng),
    ];

    for bench in simpls {
        let name = bench.name.clone();
        let outs = bench.measure_simplify_input();
        printout(&name, &outs);
    }

    let benches = [
        CovInput::from_cli("naive cov", covmap_is_interesting_naive, &cli, &rng),
        CovInput::from_cli("u8x16 cov", covmap_is_interesting_u8x16, &cli, &rng),
        CovInput::from_cli("u8x32 cov", covmap_is_interesting_u8x32, &cli, &rng),
    ];

    for bench in benches {
        let name = bench.name.clone();
        let outs = bench.measure_cov();
        printout(&name, &outs);
    }
}
