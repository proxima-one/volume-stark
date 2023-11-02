use std::env;
use std::fs::File;
use std::io::{BufRead, Read};
use bytes::Buf;
use bytes::Bytes;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use log::{error, info};
use serde_json::{json, Value};
use tokio::net::TcpStream;


type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}

fn convert_data_to_json(paths_file_name: &str, block_headers_file_name: &str) -> Result<Value> {
    info!("{:?} {:?}", paths_file_name, block_headers_file_name);
    let mut file_path = File::open(paths_file_name)?;
    let mut block_header_file_path = File::open(block_headers_file_name)?;
    let mut path_contents = String::new();
    let mut block_headers_contents = String::new();
    file_path.read_to_string(&mut path_contents)?;
    block_header_file_path.read_to_string(&mut block_headers_contents)?;

    let json_path: Value = serde_json::from_str(&path_contents)?;
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


    let url = "http://127.0.0.1:3000/generate_proof".parse::<hyper::Uri>().unwrap();
    if url.scheme_str() != Some("http") {
        info!("This test only works with 'http' URLs.");
        return Ok(());
    }
    let agg_url = "http://127.0.0.1:3000/aggregate".parse::<hyper::Uri>().unwrap();
    let proof_data_json_first = convert_data_to_json(paths_names[0].as_str(), block_names[0].as_str()).expect("Error parsing data to JSON");
    let proof_data_json_second = convert_data_to_json(paths_names[1].as_str(), block_names[1].as_str()).expect("Error parsing data to JSON");

    let binding = generate_proof(url.clone(), proof_data_json_first).await.expect("Error generating first proof");
    let first_proof = binding.as_str();
    let binding = generate_proof(url.clone(), proof_data_json_second).await.expect("Error generating first proof");
    let second_proof = binding.as_str();

    let agg_json = json!({"lhs_proof" : first_proof, "rhs_proof" : second_proof });
    let binding = aggregate_proof(agg_url.clone(), agg_json).await.expect("Error generating agg first proof");
    let mut agg_proof = binding.as_str().to_string();

    for (paths_name, block_name) in paths_names.iter().zip(block_names){
        let proof_data_json = convert_data_to_json(paths_name.as_str(), block_name.as_str()).expect("Error parsing data to JSON");
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
    let proof_b64 = data.clone()["generated_proof"]
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