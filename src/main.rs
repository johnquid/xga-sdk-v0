
use alloy_serde::WithOtherFields;
use alloy::{    
    consensus::TxEnvelope,
    contract::{ContractInstance, Interface},
    primitives::{address, Address, U256, I256, 
        keccak256, Bytes, utils::format_units},
        signers::local::PrivateKeySigner, 
        providers::{Provider, ProviderBuilder}, 
        network::{Ethereum, EthereumWallet, Network,
            AnyNetwork, TransactionBuilder, eip2718::Encodable2718},
    json_abi::JsonAbi, rpc::types::{Filter, 
        request::TransactionRequest},
    transports::http::{Client, Http},
    sol, sol_types::{SolType}, 
    dyn_abi::DynSolValue, hex::encode,
};
use reqwest::Url; use serde_json::json;
use reqwest::header::{HeaderMap, CONTENT_TYPE, HeaderValue};
use reqwest::Client as ReqwestClient;
use eyre::Result; use dotenv::dotenv;
use std::{process, env, str::FromStr};
use tokio::{runtime::Runtime,
    time::{sleep, Duration}};
    use serde_json::{Value};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OpenBidder,
    "src/abis/OpenBidder.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Auctioneer,
    "src/abis/Auctioneer.json"
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the .env file
    dotenv().ok();

    let mut rpc_url_l1: Url = env::var("RPC").expect("RPC not found in .env file").parse()?;

    let chain_id = U256::from_str_radix(
        &env::var("CHAIN_ID").expect("CHAIN_ID not found in .env file"), 10
    ).expect("Invalid value");
        println!("chain_id: {:?}", chain_id);

    let gas_limit = U256::from_str_radix(
        &env::var("MAX_GAS").expect("MAX_GAS not found in .env file"), 10
    ).expect("Invalid value");  
        println!("gas_limit: {:?}", gas_limit);

    let priority_fee = U256::from_str_radix(
        &env::var("MAX_PRIORITY_FEE_PER_GAS").expect("MAX_PRIORITY_FEE_PER_GAS not found in .env file"), 10
    ).expect("Invalid value");
        println!("priority_fee: {:?}", priority_fee);

    let owner_address = Address::from_str(
        &env::var("OWNER_ADDRESS").expect("OWNER_ADDRESS not found in .env file")
    ).unwrap();  println!("owner address: {:?}", owner_address);

    let private_key_str = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not found in .env file");
    let signer: PrivateKeySigner = private_key_str.parse().expect("should parse private key");

    // Create the EthereumWallet from the signer
    let wallet = EthereumWallet::from(signer);
    let provider_l1 = ProviderBuilder::new()
        .with_recommended_fillers()
        .network::<AnyNetwork>()
        .wallet(wallet.clone()) 
        .on_http(rpc_url_l1);
     
    // Get transaction count
    let tx_count_l1 = provider_l1.get_transaction_count(owner_address).await?;
        println!("transaction count: {:?}", tx_count_l1);
    // Get latest block number.
    let latest_block = provider_l1.get_block_number().await?;
        println!("latest block number: {:?}", latest_block);
    // Get the gas price of the network.
    let wei_per_gas = provider_l1.get_gas_price().await?;
    let base_fee = wei_per_gas * 2;
    // Convert the gas price to Gwei 
    let gwei = format_units(wei_per_gas, "gwei")?.parse::<f64>()?;
    // Print the block number.
    println!("gas price in gwei: {:?}", gwei);
    
    // Parse command line arguments
    let command_line_args: Vec<String> = env::args().collect();
    
    if command_line_args[1] == "sign" { // sign and broadcast a single tx (L1)
        if command_line_args.len() < 5 {
            println!("Usage: <command (sign | bundle)> <contract_to_transact_with> <msg.value> <function_signature> <function_args>");
            process::exit(1);
        } 
        let contract = Address::from_str(&command_line_args[2]).expect("Invalid contract address"); 
        println!("contract: {:?}", contract);
        let value = U256::from_str_radix(
            &command_line_args[3].trim(), 10
        ).expect("Invalid value");
            println!("value: {:?}", value);

        let function_signature = command_line_args[4].clone();
            println!("function_signature: {:?}", function_signature);

        let function_arguments = command_line_args[5..].to_vec();
            println!("function_arguments: {:?}", function_arguments);

        let calldata = encode_calldata(function_signature, function_arguments);
    
        let tx = TransactionRequest::default()
            .with_to(contract)
            .with_nonce(tx_count_l1)
            .with_value(value)
            .with_input(calldata)
            .with_chain_id(chain_id.try_into().expect("too large"))
            .with_gas_limit(gas_limit.try_into().expect("too large"))
            .with_max_priority_fee_per_gas(priority_fee.try_into().expect("too large"))
            .with_max_fee_per_gas(base_fee);

        // Build and sign the transaction using the `EthereumWallet` with the provided wallet.
        let tx_envelope = tx.build(&wallet).await?;
        // Send the raw transaction and retrieve the transaction receipt.
        // [Provider::send_tx_envelope] is a convenience method that encodes the transaction using
        // EIP-2718 encoding and broadcasts it to the network using [Provider::send_raw_transaction].
        let receipt = provider_l1.send_tx_envelope(tx_envelope).await?.get_receipt().await?;
        println!("Sent transaction: {}", receipt.transaction_hash);
    } 
    else { // handle events and submit bundles (L2)
        let rpc_url = env::var("BETA_BUNDLE_RPC").expect("BETA_BUNDLE_RPC not found in .env file");
        rpc_url_l1 = rpc_url.parse()?;
        let rpc_url_l2: Url = env::var("RPC_L2").expect("RPC_L2 not found in .env file").parse()?;

        let provider_l2 = ProviderBuilder::new()
            // .with_gas_estimation()
            .with_recommended_fillers() // this is includes gas estimation
            .network::<AnyNetwork>()
            .wallet(wallet.clone())
            .on_http(rpc_url_l2);

        let tx_to = Address::from_str(
            &env::var("TX_TO").expect("TX_TO not found in .env file")
        ).expect("TX_TO");  println!("tx_to: {:?}", tx_to);

        let tx_count_l2 = provider_l2.get_transaction_count(owner_address).await?;
            println!("transaction count: {:?}", tx_count_l2);

        let tx_value = U256::from_str_radix(
            &env::var("TX_VALUE").expect("TX_VALUE not found in .env file"), 10
        ).expect("Invalid tx value");
        println!("tx_value: {:?}", tx_value);

        let tx_sig_str = env::var("TX_SIG").expect("TX_SIG not found in .env file");
        let tx_args_str = env::var("TX_ARGS").expect("TX_ARGS not found in .env file");
        let tx_args: Vec<String> = tx_args_str
            .trim_start_matches('(')
            .trim_end_matches(')')
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        
        let calldata_tx_global = encode_calldata(tx_sig_str, tx_args);

        let tx_global = TransactionRequest::default()
            .with_to(tx_to)
            .with_nonce(tx_count_l1)
            .with_value(tx_value)
            .with_input(calldata_tx_global)
            .with_chain_id(chain_id.try_into().expect("too large"))
            .with_gas_limit(gas_limit.try_into().expect("too large"))
            .with_max_priority_fee_per_gas(priority_fee.try_into().expect("too large"))
            .with_max_fee_per_gas(base_fee);

        // Build and sign the transaction using the `EthereumWallet` with the provided wallet.
        let tx_with_other_fields = &WithOtherFields::new(tx_global.clone());
        let tx_envelope_global = tx_global.build(&wallet).await?;    
        let estimate = provider_l1.estimate_gas(tx_with_other_fields).await?;
    
        let bidder_address = Address::from_str(
            &env::var("BIDDER").expect("BIDDER not found in .env file")
        ).unwrap();  println!("bidder address: {:?}", bidder_address);
    
        let auctioneer_address = Address::from_str(
            &env::var("AUCTIONEER").expect("AUCTIONEER not found in .env file")
        ).unwrap();  println!("auctioneer address: {:?}", auctioneer_address);

        let auctioneer_contract = Auctioneer::new(auctioneer_address, &provider_l2);
        let bidder_contract = OpenBidder::new(bidder_address, &provider_l2);
        
        let sig_auction_closed = keccak256("AuctionSettled(uint256)".as_bytes());
        let sig_auction_opened = keccak256("AuctionOpened(uint256,uint120)".as_bytes());
        let sig_auction_paid = keccak256("AuctionPaidOut(uint256)".as_bytes());
        let sig_auction_refunded = keccak256("AuctionRefund(uint256)".as_bytes());

        //loop {
            // Create a filter to get all logs from the latest block.
            let filter = Filter::new().from_block(latest_block).address(auctioneer_address);
            // Get all logs from the latest block that match the filter.
            let logs = provider_l1.get_logs(&filter).await?;

            for log in logs {
                let topic = log.topics()[0];
                // Convert the topic to U256 directly
                let slot = U256::from_be_bytes(log.topics()[1].0);

                if topic == sig_auction_opened {
                    println!("auction opened at slot: {:?}", slot);
                 
                    let function_sig_str: &str = "openBid(uint128 weiPerGas, uint120 amountOfGas, bytes32 bundleHash)";
                    let function_name = &function_sig_str[..function_sig_str.find('(').unwrap()]; 
                    // Prepare to encode the inputs
                    let mut encoded_data = Vec::new();
                    // Append function selector (first 4 bytes of the hash)...
                    let function_selector = keccak256(function_name.as_bytes());
                    encoded_data.extend_from_slice(&function_selector[0..4]); 
                    
                    let mut encoded = <sol!(uint128)>::abi_encode(&wei_per_gas);
                    encoded_data.extend_from_slice(&encoded);
                    
                    let gas_estimate = estimate * wei_per_gas;
                    encoded = <sol!(uint120)>::abi_encode(&gas_estimate);
                    encoded_data.extend_from_slice(&encoded);

                    let hash = send_bundle(&rpc_url, &tx_envelope_global, slot).await.ok_or("Failed to get hash from send_bundle")?;
                    if let Some(hash_str) = hash.as_str() {
                        let mut hash_bytes = [0u8; 32];
                        let bytes = hash_str.as_bytes();
                    
                        // Copy the bytes into the fixed-size array
                        let len = bytes.len().min(32);
                        hash_bytes[..len].copy_from_slice(&bytes[..len]);
                    
                        // Encode as bytes32
                        let encoded = <sol!(bytes)>::abi_encode(&hash_bytes);
                        encoded_data.extend_from_slice(&encoded);
                    }
                    let calldata = Bytes::from(encoded_data);
                    let tx = TransactionRequest::default()
                        .with_to(bidder_address)
                        .with_value(U256::from(gas_estimate))
                        .with_nonce(tx_count_l2)
                        .with_input(calldata);
            
                    // Build and sign the transaction using the `EthereumWallet` with the provided wallet.
                    let tx_envelope = tx.build(&wallet).await?;
                    // Send the raw transaction and retrieve the transaction receipt.
                    // [Provider::send_tx_envelope] is a convenience method that encodes the transaction using
                    // EIP-2718 encoding and broadcasts it to the network using [Provider::send_raw_transaction].
                    let receipt = provider_l2.send_tx_envelope(tx_envelope).await?.get_receipt().await?;
                    println!("Sent submitBundles: {}", receipt.transaction_hash);
                } 
                else if topic == sig_auction_closed {
                    let bal = auctioneer_contract.balanceOf(owner_address, slot).call().await?._0;
                    if !bal.is_zero() {
                        let function_sig_str: &str = "submitBundles(uint256 slot)";
                        let function_name = &function_sig_str[..function_sig_str.find('(').unwrap()]; 
                        // Prepare to encode the inputs
                        let mut encoded_data = Vec::new();
                        // Append function selector (first 4 bytes of the hash)...
                        let function_selector = keccak256(function_name.as_bytes());
                        encoded_data.extend_from_slice(&function_selector[0..4]); 
                        
                        let encoded = <sol!(uint256)>::abi_encode(&slot);
                        encoded_data.extend_from_slice(&encoded);
                        let calldata = Bytes::from(encoded_data);

                        let tx = TransactionRequest::default()
                            .with_to(bidder_address)
                            .with_nonce(tx_count_l2)
                            .with_input(calldata);
                
                        // Build and sign the transaction using the `EthereumWallet` with the provided wallet.
                        let tx_envelope = tx.build(&wallet).await?;
                        // Send the raw transaction and retrieve the transaction receipt.
                        // [Provider::send_tx_envelope] is a convenience method that encodes the transaction using
                        // EIP-2718 encoding and broadcasts it to the network using [Provider::send_raw_transaction].
                        let receipt = provider_l2.send_tx_envelope(tx_envelope).await?.get_receipt().await?;
                        println!("Sent submitBundles: {}", receipt.transaction_hash);
                    }
                }
                else if topic == sig_auction_paid {
                    let function_sig_str: &str = "checkPendingBids(uint256 slot)";
                    let function_name = &function_sig_str[..function_sig_str.find('(').unwrap()]; 
                    // Prepare to encode the inputs
                    let mut encoded_data = Vec::new();
                    // Append function selector (first 4 bytes of the hash)...
                    let function_selector = keccak256(function_name.as_bytes());
                    encoded_data.extend_from_slice(&function_selector[0..4]); 
                    
                    let encoded = <sol!(uint256)>::abi_encode(&slot);
                    encoded_data.extend_from_slice(&encoded);
                    let calldata = Bytes::from(encoded_data);

                    let tx = TransactionRequest::default()
                        .with_to(bidder_address)
                        .with_nonce(tx_count_l2)
                        .with_input(calldata);
            
                    // Build and sign the transaction using the `EthereumWallet` with the provided wallet.
                    let tx_envelope = tx.build(&wallet).await?;
                    // Send the raw transaction and retrieve the transaction receipt.
                    // [Provider::send_tx_envelope] is a convenience method that encodes the transaction using
                    // EIP-2718 encoding and broadcasts it to the network using [Provider::send_raw_transaction].
                    let receipt = provider_l2.send_tx_envelope(tx_envelope).await?.get_receipt().await?;
                    println!("Block included. Check tx on L1: {:?}", receipt.transaction_hash);
                    process::exit(0);
                }
                else if topic == sig_auction_refunded {
                    let function_sig_str: &str = "checkPendingBids(uint256 slot)";
                    let function_name = &function_sig_str[..function_sig_str.find('(').unwrap()]; 
                    // Prepare to encode the inputs
                    let mut encoded_data = Vec::new();
                    // Append function selector (first 4 bytes of the hash)...
                    let function_selector = keccak256(function_name.as_bytes());
                    encoded_data.extend_from_slice(&function_selector[0..4]); 
                    
                    let encoded = <sol!(uint256)>::abi_encode(&slot);
                    encoded_data.extend_from_slice(&encoded);
                    let calldata = Bytes::from(encoded_data);

                    let tx = TransactionRequest::default()
                        .with_to(bidder_address)
                        .with_nonce(tx_count_l2)
                        .with_input(calldata);
            
                    // Build and sign the transaction using the `EthereumWallet` with the provided wallet.
                    let tx_envelope = tx.build(&wallet).await?;
                    // Send the raw transaction and retrieve the transaction receipt.
                    // [Provider::send_tx_envelope] is a convenience method that encodes the transaction using
                    // EIP-2718 encoding and broadcasts it to the network using [Provider::send_raw_transaction].
                    let receipt = provider_l2.send_tx_envelope(tx_envelope).await?.get_receipt().await?;
                    println!("Block missed. Trying for next auction slot.");
                }
            }
            // sleep(Duration::from_secs(2)).await;
        //}
    }  
    Ok(())
}

async fn send_bundle(bundle_rpc: &str, tx_envelope_global: &<AnyNetwork as Network>::TxEnvelope, slot: U256) -> Option<Value> {
    // Step 1: Extract the raw transaction and convert to hex
    let raw_transaction_bytes = tx_envelope_global.encoded_2718(); // TODO fix this 
    let raw_transaction_hex = encode(raw_transaction_bytes);

    // Step 2: Create the list of transactions
    let txs = vec![raw_transaction_hex];

    // Step 3: Construct the JSON-RPC request
    let req = json!({
        "jsonrpc": "2.0",
        "method": "mev_sendBetaBundle",
        "params": [{
            "txs": txs,
            "slot": slot.to_string()
        }],
        "id": 1
    });

    // Step 4: Send the request and handle the response
    let client = ReqwestClient::new();
    // Step 5: Set headers and send the request
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
 
    match client.post(bundle_rpc)
        .headers(headers)
        .json(&req)
        .send()
        .await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<Value>().await {
                    Ok(res) => res.get("result").cloned(),
                    Err(e) => {
                        eprintln!("Failed to parse JSON response: {}", e);
                        None
                    }
                }
            } else {
                eprintln!("Request failed with status: {}", response.status());
                None
            }
        },
        Err(e) => {
            eprintln!("Failed to submit bundle: {}", e);
            None
        }
    }
}

fn encode_calldata(function_signature: String, function_arguments: Vec<String>) -> Bytes {
    let function_name = &function_signature[..function_signature.find('(').unwrap()];
        println!("function name: {:?}", function_name);

    let sig = keccak256(function_signature.as_bytes());
    let function_sig = &function_signature[
        function_signature.find('(').unwrap() + 1..function_signature.find(')').unwrap()
    ];
    let function_sig_args: Vec<_> = function_sig.split(',').collect();
    // Prepare to encode the inputs
    let mut encoded_data = Vec::new();

    // Append function selector (first 4 bytes of the hash)...
    let function_selector = keccak256(function_name.as_bytes());
    encoded_data.extend_from_slice(&function_selector[0..4]);
    for (i, arg) in function_sig_args.iter().enumerate() {
        let arg_trimmed = arg.trim();
        let type_and_name: Vec<&str> = arg_trimmed.split_whitespace().collect();
        let arg_type = type_and_name[0];
        // Match the type and encode accordingly
        match arg_type {
            "uint" | "uint256" => {
                let value: U256 = function_arguments[i].parse().expect("Invalid uint");
                let encoded = <sol!(uint256)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "uint128" => {
                let value: u128 = function_arguments[i].parse().expect("Invalid uint128");
                let encoded = <sol!(uint128)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "uint120" => {
                let value: u128 = function_arguments[i].parse().expect("Invalid uint128");
                let encoded = <sol!(uint120)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "uint64" => {
                let value: u64 = function_arguments[i].parse().expect("Invalid uint64");
                let encoded = <sol!(uint64)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "uint32" => {
                let value: u32 = function_arguments[i].parse().expect("Invalid uint32");
                let encoded = <sol!(uint32)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "uint16" => {
                let value: u16 = function_arguments[i].parse().expect("Invalid uint16");
                let encoded = <sol!(uint16)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "uint8" => {
                let value: u8 = function_arguments[i].parse().expect("Invalid uint8");
                let encoded = <sol!(uint8)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "int" | "int256" => {
                let value: I256 = function_arguments[i].parse().expect("Invalid int");
                let encoded = <sol!(int256)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "int64" => {
                let value: i64 = function_arguments[i].parse().expect("Invalid int64");
                let encoded = <sol!(int64)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "int32" => {
                let value: i32 = function_arguments[i].parse().expect("Invalid int32");
                let encoded = <sol!(int32)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "int16" => {
                let value: i16 = function_arguments[i].parse().expect("Invalid int16");
                let encoded = <sol!(int16)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "int8" => {
                let value: i8 = function_arguments[i].parse().expect("Invalid int8");
                let encoded = <sol!(int8)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "address" => {
                let value: Address = function_arguments[i].parse().expect("Invalid address");
                let encoded = <sol!(address)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "string" => {
                let value = function_arguments[i].clone();
                let encoded = <sol!(string)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "bytes" | "bytes32" => {
                let value = function_arguments[i].as_bytes().to_vec();
                let encoded = <sol!(bytes)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            },
            "bool" => {
                let value: bool = function_arguments[i].parse().expect("Invalid bool");
                let encoded = <sol!(bool)>::abi_encode(&value);
                encoded_data.extend_from_slice(&encoded);
            }
            _ => panic!("Unsupported type!"),
        }
    }
    // Convert encoded data to Bytes for TransactionRequest
    return Bytes::from(encoded_data);
}