
use alloy::{
    primitives::{address, Address, U256, hex,
        Bytes, utils::format_units},
        signers::local::PrivateKeySigner, 
        providers::{Provider, ProviderBuilder}, 
        network::{AnyNetwork, 
        EthereumWallet, TransactionBuilder},
    rpc::types::request::TransactionRequest,
    sol, json_abi::{Function, JsonAbi},
    dyn_abi::{DynSolType, DynSolValue, JsonAbiExt},
};
use eyre::Result;
use dotenv::dotenv;
use std::str::FromStr;
use std::process;
use std::env;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        .wallet(wallet.clone())
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
        ); println!("contract: {:?}", contract);
        let value = U256::from_str_radix(
            &command_line_args[3].trim(), 10
        ).expect("Invalid value");
        println!("value: {:?}", value);

        let function_signature = command_line_args[4].clone();
        println!("function_signature: {:?}", function_signature);

        let function_arguments = command_line_args[5..].to_vec();
        println!("function_arguments: {:?}", function_arguments);

         // Parse the function signature
        let function = Function::parse(&function_signature)?;

        // Prepare arguments for ABI encoding
        let mut abi_args = Vec::new();

        // Process each argument based on the type
        for (i, input) in function.inputs.iter().enumerate() {
            if let Some(internal_type) = &input.internal_type {
                match internal_type.to_string().as_str() {
                    "uint" => {
                        let value: U256 = function_arguments[i].parse().expect("Invalid uint");
                        abi_args.push(DynSolValue::Uint(value.into(), 256));
                    },
                    "address" => {
                        let value: Address = function_arguments[i].parse().expect("Invalid address");
                        abi_args.push(DynSolValue::Address(value));
                    },
                    "bytes" => {
                        let value = function_arguments[i].as_bytes().to_vec();
                        abi_args.push(DynSolValue::Bytes(value));
                    },
                    "bool" => {
                        let value: bool = function_arguments[i].parse().expect("Invalid bool");
                        abi_args.push(DynSolValue::Bool(value));
                    }
                    _ => panic!("Unsupported type!"),
                }
            }
        }
        // ABI encode the function call
        let encoded_data = function.abi_encode_input(&abi_args)?;
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

        // Build and sign the transaction using the `EthereumWallet` with the provided wallet.
        let tx_envelope = tx.build(&wallet).await?;
        
        // Send the raw transaction and retrieve the transaction receipt.
        // [Provider::send_tx_envelope] is a convenience method that encodes the transaction using
        // EIP-2718 encoding and broadcasts it to the network using [Provider::send_raw_transaction].
        let receipt = provider.send_tx_envelope(tx_envelope).await?.get_receipt().await?;
        println!("Sent transaction: {}", receipt.transaction_hash);
    } else {
        // TODO
    }    
    Ok(())
}
