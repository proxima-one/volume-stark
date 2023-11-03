use std::{env, fs};
use std::io::Read;
use base64::{Engine};
use base64::engine::general_purpose;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use bytes::Buf;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use ethereum_types::{H256, U256};
use itertools::Itertools;
use log::{error, info};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::fri::FriParams;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use plonky2::util::timing::TimingTree;
use serde_json::{json, Value};
use anyhow::Result;
use maru_volume_stark::circom_verifier::{generate_proof_base64, generate_verifier_config};
use maru_volume_stark::fixed_recursive_verifier::AllRecursiveCircuits;
use maru_volume_stark::proof::PublicValues;
use http_body_util::BodyExt;
use std::net::SocketAddr;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpListener;
use hyper::body::{Body as HttpBody, Bytes, Frame};
use hyper::service::service_fn;
use hyper::{Error, Method, Response, StatusCode};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use std::borrow::Borrow;
use serde::Deserialize;
use maru_volume_stark::all_stark::AllStark;
use maru_volume_stark::block_header::{Header, read_headers_from_request};
use maru_volume_stark::config::StarkConfig;
use maru_volume_stark::generation::PatriciaInputs;
use maru_volume_stark::patricia_merkle_trie::{convert_to_tree, PatriciaMerklePath, read_paths_from_json_request};

type F = GoldilocksField;

const D: usize = 2;

type C = PoseidonGoldilocksConfig;


struct Body {
    _marker: PhantomData<*const ()>,
    data: Option<Bytes>,
}

impl From<String> for Body {
    fn from(a: String) -> Self {
        Body {
            _marker: PhantomData,
            data: Some(a.into()),
        }
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.get_mut().data.take().map(|d| Ok(Frame::data(d))))
    }
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}


#[derive(Debug, Deserialize)]
struct JsonRequest {
    merkle_paths: Vec<PatriciaMerklePath>,
    block_header: Vec<Header>,
}

fn main() {
    init_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        error!("Usage: {} <circuit_file>", args[0]);
        std::process::exit(1);
    }
    let circuit_path = &args[1];
    let binary_data = fs::read(circuit_path).unwrap();
    let server_http2 = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, http1_server(&binary_data)).unwrap();
    });
    server_http2.join().unwrap();
}

fn construct_error_response(status: StatusCode, error_message: &str) -> Response<Body> {
    let error_json = json!({
        "error": error_message,
    });
    let json = serde_json::to_string(&error_json).expect("Error converting json to string");
    let mut response = Response::new(Body::from(json));
    *response.status_mut() = status;
    response
}

async fn http1_server(binary_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut stdout = io::stdout();

    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();
    let listener = TcpListener::bind(addr).await?;
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer {
        _phantom: PhantomData::<C>,
    };
    let counter: Arc<Mutex<AllRecursiveCircuits<GoldilocksField, C, 2>>> = Arc::new(Mutex::new(AllRecursiveCircuits::from_bytes(&binary_data, &gate_serializer, &generator_serializer).unwrap()));

    stdout
        .write_all(format!("Listening on http://{}", addr).as_bytes())
        .await
        .unwrap();
    stdout.flush().await.unwrap();


    loop {
        let (stream, _) = listener.accept().await?;

        let io = IOTypeNotSend::new(TokioIo::new(stream));

        let cnt = Arc::clone(&counter);

        let service = service_fn(move |req| {
            let cnt_clone = Arc::clone(&cnt);
            async move {
                match (req.method(), req.uri().path()) {
                    (&Method::POST, "/aggregate") => {
                        let recursive_circuit_ref: MutexGuard<_> = match cnt_clone.lock() {
                            Ok(lock) => lock,
                            Err(err) => match err {
                                PoisonError { .. } => {
                                    let recovered_lock = err.into_inner();
                                    recovered_lock
                                }
                            },
                        };
                        let whole_body_result = req.collect().await;
                        if let Err(err) = whole_body_result {
                            return Ok::<_, Error>(construct_error_response(StatusCode::INTERNAL_SERVER_ERROR, "REQUEST_BODY_ERROR"));
                        }
                        let whole_body = whole_body_result.unwrap().aggregate();
                        let data_result = serde_json::from_reader(whole_body.reader());
                        if let Err(err) = data_result {
                            return Ok::<_, Error>(construct_error_response(StatusCode::INTERNAL_SERVER_ERROR, "JSON_NOT_PARSED"));
                        }
                        let data: serde_json::Value = data_result.unwrap();
                        let lhs_proof = match data["lhs_proof"].as_str() {
                            Some(lhs_proof) => {
                                lhs_proof
                            }
                            None => {
                                return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "LHS_PROOF_NOT_INCLUDED"));
                            }
                        };

                        let rhs_proof = match data["rhs_proof"].as_str() {
                            Some(rhs_proof) => {
                                rhs_proof
                            }
                            None => {
                                return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "RHS_PROOF_NOT_INCLUDED"));
                            }
                        };

                        let mut lhs_proof_bytes = Vec::<u8>::new();
                        let mut rhs_proof_bytes = Vec::<u8>::new();

                        let decode_lhs_proof = general_purpose::STANDARD
                            .decode_vec(lhs_proof, &mut lhs_proof_bytes);
                        let decode_rhs_proof = general_purpose::STANDARD
                            .decode_vec(rhs_proof, &mut rhs_proof_bytes);

                        if let Err(err) = decode_lhs_proof {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "LHS_PROOF_NOT_DECODED"));
                        }

                        if let Err(err) = decode_rhs_proof {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "RHS_PROOF_NOT_DECODED"));
                        }

                        let lhs_is_agg = lhs_proof_bytes.clone().last().unwrap().clone() != 0;
                        let rhs_is_agg = rhs_proof_bytes.clone().last().unwrap().clone() != 0;
                        lhs_proof_bytes.pop();
                        rhs_proof_bytes.pop();

                        let common_data = CommonCircuitData {
                            fri_params: FriParams {
                                degree_bits: recursive_circuit_ref.root.circuit.common.degree_bits(),
                                ..recursive_circuit_ref.root.circuit.common.fri_params.clone()
                            },
                            ..recursive_circuit_ref.root.circuit.common.clone()
                        };

                        let timing = TimingTree::new("Proof aggregation", log::Level::Error);
                        let first_proof_result: Result<ProofWithPublicInputs<GoldilocksField, C, 2>> = ProofWithPublicInputs::from_bytes(lhs_proof_bytes.clone(), &common_data);
                        let second_proof_result: Result<ProofWithPublicInputs<GoldilocksField, C, 2>> = ProofWithPublicInputs::from_bytes(rhs_proof_bytes.clone(), &common_data);

                        if let Err(err) = first_proof_result {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "LHS_PROOF_NOT_CORRECT"));
                        }

                        if let Err(err) = second_proof_result {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "RHS_PROOF_NOT_CORRECT"));
                        }

                        let first_proof = first_proof_result.unwrap();
                        let second_proof = second_proof_result.unwrap();

                        let pi_1 = first_proof.public_inputs.iter().take(24).map(|x| x.0.to_le_bytes()[0..4].to_vec()).concat();
                        let starting_sum = U256::from_little_endian(&pi_1[0..32]);
                        let mut starting_blockhash = H256::from_slice(&pi_1[32..64]);
                        starting_blockhash.0.reverse();
                        let pi_2 = second_proof.public_inputs.iter().take(24).map(|x| x.0.to_le_bytes()[0..4].to_vec()).concat();
                        let ending_sum = U256::from_little_endian(&pi_2[0..32]);
                        let mut ending_blockhash = H256::from_slice(&pi_2[64..96]);
                        let total_sum = starting_sum + ending_sum;
                        ending_blockhash.0.reverse();
                        let pv = PublicValues {
                            total_sum,
                            starting_blockhash,
                            ending_blockhash,
                        };


                        let agg_proof_result = recursive_circuit_ref.prove_aggregation(lhs_is_agg, &first_proof, rhs_is_agg, &second_proof, pv);

                        let result: Result<(ProofWithPublicInputs<GoldilocksField, C, 2>, PublicValues), Response<Body>> = agg_proof_result.map_err(|err| {
                            let error_message = format!("Error in prove_aggregation: {:?}", err);
                            construct_error_response(StatusCode::BAD_REQUEST, &error_message)
                        });
                        timing.print();
                        let agg_proof = match result {
                            Ok(result) => {
                                result
                            }
                            Err(error_response) => {
                                return Ok::<_, Error>(error_response);
                            }
                        };
                        let mut actual_proof = agg_proof.0.to_bytes();
                        actual_proof.push(1u8);
                        let conf = generate_verifier_config(&agg_proof.0).expect("Error to generate verifier config");
                        let proof_base64_json = generate_proof_base64(&agg_proof.0, &conf).expect("Error to generate base64 proof");
                        let b64_agg_proof = general_purpose::STANDARD.encode(&actual_proof);
                        let pis_string = serde_json::to_string(&agg_proof.1).expect("Error to convert pis to string");
                        let data = json!({
                            "aggregated_proof": b64_agg_proof,
                            "json_proof": proof_base64_json,
                            "public_values": pis_string
                        });
                        let json = serde_json::to_string(&data).expect("Error converting json to string");
                        let response = Response::new(Body::from(json));
                        Ok::<_, Error>(response)
                    }
                    (&Method::POST, "/generate_proof") => {
                        let recursive_circuit_ref: MutexGuard<_> = match cnt_clone.lock() {
                            Ok(lock) => lock,
                            Err(err) => match err {
                                PoisonError { .. } => {
                                    let recovered_lock = err.into_inner();
                                    recovered_lock
                                }
                            },
                        };
                        let whole_body_result = req.collect().await;
                        if let Err(err) = whole_body_result {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::INTERNAL_SERVER_ERROR, "REQUEST_BODY_ERROR"));
                        }
                        let whole_body = whole_body_result.unwrap().aggregate();
                        let data_result = serde_json::from_reader(whole_body.reader());
                        if let Err(err) = data_result {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::INTERNAL_SERVER_ERROR, "JSON_NOT_PARSED"));
                        }
                        let data: serde_json::Value = data_result.unwrap();
                        let empty_vec = vec![];
                        let merkle_paths_json_values = match data["merkle_paths"].as_array() {
                            Some(values) => values,
                            None => {
                                &empty_vec
                            }
                        };


                        let block_headers_json_values = match data["block_headers"].as_array() {
                            Some(values) => {
                                values
                            }
                            None => {
                                return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "BLOCK_HEADERS_NOT_INCLUDED"));
                            }
                        };

                        let merkle_paths_result: Result<Vec<PatriciaMerklePath>> = if merkle_paths_json_values.is_empty() {
                            Ok(vec![])
                        } else { read_paths_from_json_request(merkle_paths_json_values) };
                        if let Err(err) = merkle_paths_result {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "MERKLE_PATHS_PARSING_ERROR"));
                        }
                        let merkle_paths = merkle_paths_result.unwrap();

                        let block_headers_result: Result<Vec<Header>> = read_headers_from_request(block_headers_json_values);
                        if let Err(err) = block_headers_result {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "BLOCK_HEADERS_PARSING_ERROR"));
                        }
                        let block_headers = block_headers_result.unwrap();

                        let tries = if merkle_paths.is_empty() {
                            vec![]
                        }else{
                            let converted_trie = convert_to_tree(&merkle_paths);
                            if let Err(err) = converted_trie {
                                info!("ERROR : {:?}", err);
                                return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "TRIES_PARSING_ERROR"));
                            } else{
                                converted_trie.unwrap()
                            }
                        };

                        let patricia_inputs = PatriciaInputs {
                            pmt: tries,
                            starting_blockhash: block_headers[0].parent_hash.clone(),
                            blockheaders: block_headers,
                        };
                        let config = StarkConfig::standard_fast_config();
                        let all_stark = AllStark::<F, D>::default();
                        let mut timing = TimingTree::new("Generate recursive proof", log::Level::Error);
                        let prove_result = recursive_circuit_ref.prove_root(
                            &all_stark,
                            &config,
                            Default::default(),
                            patricia_inputs.clone(),
                            &mut timing,
                        );
                        timing.print();
                        if let Err(err) = prove_result {
                            info!("ERROR : {:?}", err);
                            return Ok::<_, Error>(construct_error_response(StatusCode::BAD_REQUEST, "PROOF_GENERATION_ERROR"));
                        }
                        let (root_proof, proof_pis) = prove_result.unwrap();
                        let is_aggregated = 0u8;
                        let mut proof_bytes = root_proof.to_bytes();
                        proof_bytes.push(is_aggregated);
                        let conf = generate_verifier_config(&root_proof).expect("Error to generate verifier config");
                        let proof_base64_json = generate_proof_base64(&root_proof, &conf).expect("Error to generate base64 proof");
                        let b64_agg_proof = general_purpose::STANDARD.encode(&proof_bytes);
                        let pis_string = serde_json::to_string(&proof_pis).expect("Error to convert pis to string");
                        let data = json!({
                            "generated_proof": b64_agg_proof,
                            "json_proof": proof_base64_json,
                            "public_values": pis_string
                        });
                        let json = serde_json::to_string(&data).expect("Error converting json to string");
                        let response = Response::new(Body::from(json));
                        Ok::<_, Error>(response)
                    }
                    _ => {
                        let mut response = Response::new(Body::from(format!("Not found")));
                        *response.status_mut() = StatusCode::NOT_FOUND;
                        Ok::<_, Error>(response)
                    }
                }
            }
        });


        tokio::task::spawn_local(async move {
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}


struct IOTypeNotSend {
    _marker: PhantomData<*const ()>,
    stream: TokioIo<TcpStream>,
}

impl IOTypeNotSend {
    fn new(stream: TokioIo<TcpStream>) -> Self {
        Self {
            _marker: PhantomData,
            stream,
        }
    }
}

impl hyper::rt::Write for IOTypeNotSend {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl hyper::rt::Read for IOTypeNotSend {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}