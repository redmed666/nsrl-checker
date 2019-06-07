extern crate argparse;
extern crate hashbrown;
extern crate r2pipe;
extern crate ring;
extern crate serde_json;

use argparse::{ArgumentParser, Store, StoreOption, StoreTrue};
use hashbrown::HashMap;
use r2pipe::{R2Pipe, R2PipeSpawnOptions};
use ring::{digest, test};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufRead, BufReader, Error, Read};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn replace(s: &str, old: &str, new: &str, n: &mut i8) -> String {
    if old == new || *n == 0 {
        return String::from(s);
    } else {
        let m = s.matches(old).count() as i8;
        if m == 0 {
            return String::from(s);
        } else if *n < 0 || m < *n {
            *n = m;
        }
        let mut t = String::new();
        let mut w = 0;
        let mut start = 0;

        for i in 0..(*n) {
            let mut j = start;
            if old.len() == 0 {
                if i > 0 {
                    let wid = s[start..].len();
                    j += wid;
                }
            } else {
                j += s[start..].find(old).unwrap();
            }
            t.push_str(&s[start..j]);
            t.push_str(new);
            start = j + old.len();
        }
        t.push_str(&s[start..]);
        t
    }
}

fn parse_nsrl_file(h_nsrl: &mut File) -> Result<HashMap<Vec<u8>, u8>, Error> {
    println!("[*] Parsing NSRL File");
    let mut results = HashMap::new();
    let decoder = BufReader::new(h_nsrl);

    let lines = decoder.lines();
    for (index, line) in lines.enumerate() {
        // skip header
        if index == 0 {
            continue;
        }
        let line = line.unwrap();
        let hashes: Vec<&str> = line.split(",").collect();

        let hash = hashes.get(0).unwrap().replace("\"", "");
        let hash = test::from_hex(hash.as_str()).unwrap();

        results.insert(hash, 1);
    }
    println!("[*] Finished parsing NSRL File");
    Ok(results)
}

fn hash_file(filepath: &str) -> digest::Digest {
    let mut f = File::open(filepath).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf);
    let hash = digest::digest(&digest::SHA1, &buf[..]);
    hash
}

fn is_safe(filepath: &str, safe_hashes: &HashMap<Vec<u8>, u8>) -> bool {
    let mut safe = false;
    let hash = hash_file(filepath);
    let hash = hash.as_ref();
    if safe_hashes.contains_key(hash) {
        safe = true;
    }
    safe
}

fn is_signed(filepath: &str, r2p: &mut r2pipe::R2Pipe) -> bool {
    let mut signed = false;
    let cmd_open_file = String::from("o ") + filepath;
    r2p.cmd(cmd_open_file.as_str());
    let info = match r2p.cmdj("ij") {
        Ok(v) => v,
        Err(e) => {
            println!("Error: {}", e);
            return signed;
        }
    };
    if info.find("bin") != None {
        if info["bin"].find("signed") != None {
            signed = info["bin"]["signed"].is_boolean();
        }
    }
    r2p.cmd("o--"); // close all files
    signed
}

fn check_exe(
    vec_paths: Vec<Vec<String>>,
    hashes: std::sync::Arc<HashMap<Vec<u8>, u8>>,
    unsafe_unsigned_dir: std::sync::Arc<String>,
    unsafe_signed_dir: std::sync::Arc<String>,
    safe_dir: std::sync::Arc<String>,
) -> Vec<thread::JoinHandle<()>> {
    let mut threads = Vec::new();
    for v_paths in vec_paths {
        let hashes_cpy = hashes.clone();
        let unsafe_unsigned_dir_cpy = unsafe_unsigned_dir.clone();
        let unsafe_signed_dir_cpy = unsafe_signed_dir.clone();
        let safe_dir_cpy = safe_dir.clone();

        let thr = thread::spawn(move || {
            let options = R2PipeSpawnOptions {
                exepath: "r2".to_owned(),
                args: vec!["-2"],
            };
            let r2p = R2Pipe::spawn("-", Some(options));
            let mut r2p = match r2p {
                Ok(v) => v,
                Err(e) => {
                    println!("R2 Error {:?}", e);
                    R2Pipe::open().unwrap()
                }
            };
            for path in v_paths {
                let mut safe = false;

                safe = is_safe(path.as_str(), hashes_cpy.as_ref());
                let path_cpy = path.clone();
                let filename = path_cpy.split("/").last().unwrap();
                let old_file = path.clone();
                let mut new_file = String::new();

                if safe == true {
                    new_file = safe_dir_cpy.to_string() + "/" + filename;
                } else {
                    let signed = is_signed(path.as_str(), &mut r2p);

                    if signed == true {
                        new_file = unsafe_signed_dir_cpy.to_string() + "/" + filename;
                    } else {
                        new_file = unsafe_unsigned_dir_cpy.to_string() + "/" + filename;
                    }
                }
                println!("[*] Copying {} to {}", old_file.clone(), new_file.clone());
                let mut f =
                    fs::File::create(new_file.clone()).expect("error when creating new file");
                fs::copy(old_file, new_file);
            }
            r2p.close();
        });
        threads.push(thr);
    }
    threads
}

fn main() {
    let now = Instant::now();
    let mut nsrl_file = "".to_string();
    let mut exe_dir = "".to_string();
    let mut hash_algo = "".to_string();
    let mut out_dir = "".to_string();
    let mut nmb_threads: Option<usize> = None;

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("NSRL Checker");
        ap.refer(&mut nsrl_file)
            .add_option(&["-n", "--nsrl"], Store, "NSRL File path")
            .required();
        ap.refer(&mut exe_dir)
            .add_option(
                &["-e", "--exedir"],
                Store,
                "Directory containing the exe to check",
            )
            .required();
        ap.refer(&mut hash_algo)
            .add_option(&["-H", "--hash"], Store, "Hash algorithm to use");
        ap.refer(&mut out_dir)
            .add_option(&["-o", "--outdir"], Store, "Output directory")
            .required();
        ap.refer(&mut nmb_threads).add_option(
            &["-t", "--threads"],
            StoreOption,
            "Number of threads",
        );
        ap.parse_args_or_exit();
    }

    let nmb_threads = match nmb_threads {
        Some(v) => v,
        None => 10,
    };
    let mut h_nsrl = File::open(nsrl_file).unwrap();
    let hashes = Arc::new(parse_nsrl_file(&mut h_nsrl).unwrap());

    println!(
        "Time elapsed for parsing NSRL file: {:?}s and {:?}ns",
        now.elapsed(),
        now.elapsed().subsec_nanos()
    );

    let unsafe_signed_dir = out_dir.clone() + "/unsafe/signed";
    let unsafe_unsigned_dir = out_dir.clone() + "/unsafe/unsigned";
    let safe_dir = out_dir + "/safe";
    fs::create_dir_all(unsafe_signed_dir.clone());
    fs::create_dir_all(unsafe_unsigned_dir.clone());
    fs::create_dir_all(safe_dir.clone());

    let paths = fs::read_dir(exe_dir).unwrap();

    let mut vec_paths: Vec<Vec<String>> = Vec::new();
    let mut vec_paths_tmp: Vec<String> = Vec::new();
    let mut counter = 0;
    let paths: Vec<std::result::Result<std::fs::DirEntry, std::io::Error>> = paths.collect();
    let paths_len = paths.len();
    let exe_per_thread = paths_len / nmb_threads;

    for path in paths {
        let path = String::from(path.unwrap().path().to_str().unwrap());
        vec_paths_tmp.push(path);
        if counter < exe_per_thread {
            counter += 1;
        } else {
            vec_paths.push(vec_paths_tmp);
            vec_paths_tmp = Vec::new();
            counter = 0;
        }
    }
    vec_paths.push(vec_paths_tmp);

    let unsafe_unsigned_dir = Arc::new(unsafe_unsigned_dir);
    let unsafe_signed_dir = Arc::new(unsafe_signed_dir);
    let safe_dir = Arc::new(safe_dir);
    let threads = check_exe(
        vec_paths,
        hashes,
        unsafe_unsigned_dir,
        unsafe_signed_dir,
        safe_dir,
    );

    for thr in threads {
        thr.join();
    }

    println!(
        "Time elapsed for checking files: {:?}m {:?}s",
        now.elapsed().as_secs() / 60,
        now.elapsed().as_secs() % 60
    );
}
