
use alloy::{
    primitives::{address, Address, U256, 
        keccak256, Bytes, utils::format_units},
        signers::local::PrivateKeySigner, 
        providers::{Provider, ProviderBuilder}, 
        network::{AnyNetwork, 
        EthereumWallet, TransactionBuilder},
    rpc::types::request::TransactionRequest,
    sol, sol_types::{SolCall, SolType}
};
use eyre::Result;
use dotenv::dotenv;
use std::str::FromStr;
use std::process;
use std::env;
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    // Load the .env file
    dotenv().ok();
    // Set up the HTTP transport which is consumed by the RPC client.
    let rpc_url = env::var("RPC").expect("RPC not found in .env file").parse()?;

    // Set up the HTTP transport which is consumed by the RPC client.
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
    );
    println!("owner address: {:?}", owner_address);

    let private_key_str = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not found in .env file");
    let signer: PrivateKeySigner = private_key_str.parse().expect("should parse private key");

    // Create the EthereumWallet from the signer
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .network::<AnyNetwork>()
        .wallet(wallet)
        .on_http(rpc_url);
     
    // Get transaction count
    let tx_count = provider.get_transaction_count(owner_address.unwrap()).await?;
    println!("transaction count: {:?}", tx_count);
    // Get latest block number.
    let latest_block = provider.get_block_number().await?;
    println!("latest block number: {:?}", latest_block);
    // Get the gas price of the network.
    let wei_per_gas = provider.get_gas_price().await?;
    // Convert the gas price to Gwei 
    let gwei = format_units(wei_per_gas, "gwei")?.parse::<f64>()?;
    // Print the block number.
    println!("gas price in gwei: {:?}", gwei);
    
    // Parse command line arguments
    let command_line_args: Vec<String> = env::args().collect();
    if command_line_args.len() < 5 || (
        command_line_args[1] != "sign" && command_line_args[1] != "bidder"
    ) {
        println!("Usage: <command (sign | bundle)> <contract_to_transact_with> <msg.value> <function_signature> <function_args>");
        process::exit(1);
    } 
    if command_line_args[1] == "sign" {
        let contract = Address::from_str(
            &command_line_args[2]).expect("Invalid contract address"
        );
        let value = U256::from_str_radix(
            &command_line_args[3].trim(), 10
        ).expect("Invalid value");
        
        let function_signature = command_line_args[4].clone();
        let function_name = &function_signature[..function_signature.find('(').unwrap()];
        let function_arguments = command_line_args[5..].to_vec();
        
        println!("contract: {:?}", contract);
        println!("value: {:?}", value);
        println!("value: {:?}", value);
        println!("function name: {:?}", function_name);
        println!("function_signature: {:?}", function_signature);
        println!("function_arguments: {:?}", function_arguments);

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
                "uint" => {
                    let value: U256 = function_arguments[i].parse().expect("Invalid uint");
                    let encoded = <sol!(uint256)>::abi_encode(&value);
                    encoded_data.extend_from_slice(&encoded);
                },
                "address" => {
                    let value: Address = function_arguments[i].parse().expect("Invalid address");
                    let encoded = <sol!(address)>::abi_encode(&value);
                    encoded_data.extend_from_slice(&encoded);
                },
                "bytes" => {
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
        let input = Bytes::from(encoded_data);
        let tx = TransactionRequest::default()
            .with_to(contract)
            .with_nonce(tx_count)
            .with_value(value)
            .with_input(input)
            .with_chain_id(chain_id.try_into().expect("too large"))
            .with_gas_limit(gas_limit.try_into().expect("too large"))
            .with_max_priority_fee_per_gas(priority_fee.try_into().expect("too large"))
            .with_max_fee_per_gas(wei_per_gas * 2);

        // Send the transaction and wait for inclusion.
        // let tx_hash = provider.send_transaction(tx).await?.watch().await?;
        // println!("Sent transaction: {tx_hash}");
    } else {
        // TODO
    }    
    Ok(())
}
