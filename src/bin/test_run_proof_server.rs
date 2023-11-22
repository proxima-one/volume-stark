use std::env;
use std::fs::File;
use std::io::{BufRead, Read};
use bytes::Buf;
use bytes::Bytes;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::tokio::TokioIo;
use log::{error, info};
use log::Level::Error;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use regex::Regex;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}

fn convert_data_to_json(paths_file_name: Option<&str>, block_headers_file_name: &str) -> Result<Value> {
    let json_path = match paths_file_name {
        None => { Value::String("[]".to_string()) }
        Some(file_name) => {
            let mut file_path = File::open(file_name)?;
            let mut path_contents = String::new();
            file_path.read_to_string(&mut path_contents)?;
            let json_path: Value = serde_json::from_str(&path_contents)?;
            json_path
        }
    };
    let mut block_header_file_path = File::open(block_headers_file_name)?;
    let mut block_headers_contents = String::new();
    block_header_file_path.read_to_string(&mut block_headers_contents)?;
    let block_headers: Value = serde_json::from_str(&block_headers_contents)?;
    let final_json = json!({"merkle_paths": json_path, "block_headers": block_headers});
    Ok(final_json)
}


#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        error!("Usage: {} <paths_list> <block_headers_list>", args[0]);
        std::process::exit(1);
    }
    let paths_list_file_name = &args[1];
    let block_headers_list_file_name = &args[2];

    let file = File::open(paths_list_file_name)?;
    let reader = std::io::BufReader::new(file);
    let mut paths_names: Vec<String> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        paths_names.push(line);
    }

    let file = File::open(block_headers_list_file_name)?;
    let reader = std::io::BufReader::new(file);
    let mut block_names: Vec<String> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        block_names.push(line);
    }

    let re = Regex::new(r"(\d+)-(\d+)\.json").unwrap();
    let mut paths_with_ranges: Vec<Option<&str>> = Vec::new();

    for block_name in block_names.clone() {
        let mut matching_path: Option<&str> = None;
        if let Some(captures_block) = re.captures(&*block_name) {
            let start_block = captures_block.get(1).unwrap().as_str();
            let end_block = captures_block.get(2).unwrap().as_str();
            if !paths_names.is_empty() {
                for path_name in &paths_names {
                    if let Some(captures) = re.captures(path_name) {
                        let start = captures.get(1).unwrap().as_str();
                        let end = captures.get(2).unwrap().as_str();

                        if start_block == start && end_block == end {
                            matching_path = Some(path_name);
                            break;
                        }
                    }
                }
            }
        } else {
            panic!("Wrong block_header format");
        }

        paths_with_ranges.push(matching_path);
    }


    let url = "http://127.0.0.1:3000/generate_proof".parse::<hyper::Uri>().unwrap();
    if url.scheme_str() != Some("http") {
        info!("This test only works with 'http' URLs.");
        return Ok(());
    }
    let agg_url = "http://127.0.0.1:3000/aggregate".parse::<hyper::Uri>().unwrap();
    let proof_data_json_first = convert_data_to_json(paths_with_ranges[0], block_names[0].as_str()).expect("Error parsing data to JSON");
    let proof_data_json_second = convert_data_to_json(paths_with_ranges[1], block_names[1].as_str()).expect("Error parsing data to JSON");

    let binding = generate_proof(url.clone(), proof_data_json_first).await.expect("Error generating first proof");
    let first_proof = binding.as_str();
    let binding = generate_proof(url.clone(), proof_data_json_second).await.expect("Error generating first proof");
    let second_proof = binding.as_str();

    let agg_json = json!({"lhs_proof" : first_proof, "rhs_proof" : second_proof });
    let binding = aggregate_proof(agg_url.clone(), agg_json).await.expect("Error generating agg first proof");
    let mut agg_proof = binding.as_str().to_string();

    for (paths_name, block_name) in paths_with_ranges.iter().zip(block_names).skip(2) {
        let proof_data_json = convert_data_to_json(*paths_name, block_name.as_str()).expect("Error parsing data to JSON");
        let binding = generate_proof(url.clone(), proof_data_json).await.expect("Error generating first proof");
        let first_proof = binding.as_str();
        let agg_json = json!({"lhs_proof" : agg_proof, "rhs_proof" : first_proof });
        let result = aggregate_proof(agg_url.clone(), agg_json).await.expect("Error generating agg first proof");
        agg_proof = result.as_str().to_string();
    }


    Ok(())
}

async fn generate_proof(url: hyper::Uri, json_value: Value) -> Result<String> {
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let authority = url.authority().unwrap().clone();

    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header(hyper::header::HOST, authority.as_str())
        .body(Full::<Bytes>::new(Bytes::from(json_value.to_string())))?;
    let mut res = sender.send_request(req).await?;
    let whole_body = res.collect().await.expect("Error result from request").aggregate();
    let data: serde_json::Value = serde_json::from_reader(whole_body.reader()).expect("JSON not decoded");
    let proof_b64 = data.clone()["aggregated_proof"]
        .as_str()
        .expect("Proof data not included")
        .to_string();
    println!("\n\nDone!");
    Ok(proof_b64)
}

async fn aggregate_proof(url: hyper::Uri, json_value: Value) -> Result<(String)> {
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let authority = url.authority().unwrap().clone();

    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header(hyper::header::HOST, authority.as_str())
        .body(Full::<Bytes>::new(Bytes::from(json_value.to_string())))?;
    let mut res = sender.send_request(req).await?;
    let whole_body = res.collect().await.expect("Error result from request").aggregate();
    let data: serde_json::Value = serde_json::from_reader(whole_body.reader()).expect("JSON not decoded");
    let proof_b64 = data.clone()["aggregated_proof"]
        .as_str()
        .expect("Proof data not included")
        .to_string();
    println!("\n\nDone!");
    Ok((proof_b64))
}