//! Small Bitcoin Core-compatible REST surface used by remote clients.

use alloc::sync::Arc;
use std::str::FromStr;

use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin_rs_primitives::Hash256;
use sonic_rs::{Value, json};

use crate::context::{BlockRecord, Context};
use crate::error::RpcError;

const DEFAULT_HEADER_COUNT: u32 = 5;
const MAX_HEADER_COUNT: u32 = 2_000;

/// HTTP response produced by a REST route.
#[derive(Debug, Eq, PartialEq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// HTTP reason phrase.
    pub reason: &'static str,
    /// MIME type.
    pub content_type: &'static str,
    /// Response body.
    pub body: Vec<u8>,
}

/// Routes one REST request.
#[must_use]
pub fn route(ctx: &Arc<Context>, path: &str, query: &str, enabled: bool) -> Response {
    if !enabled {
        return not_found();
    }
    if path == "/rest/chaininfo.json" {
        return json_response(crate::handlers::chain::getblockchaininfo(ctx, &json!([])));
    }
    if let Some(rest) = path.strip_prefix("/rest/headers/") {
        return route_headers(ctx, rest, query);
    }
    not_found()
}

fn route_headers(ctx: &Arc<Context>, suffix: &str, query: &str) -> Response {
    let Some((hash_text, format)) = suffix.rsplit_once('.') else {
        return not_found();
    };
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request("invalid block hash");
    };
    let count = match parse_count(query) {
        Ok(count) => count,
        Err(response) => return response,
    };
    let records = header_records(ctx, hash, count);
    if records.is_empty() {
        return not_found();
    }
    let headers: Vec<Header> = records.iter().filter_map(decode_header).collect();
    if headers.is_empty() {
        return not_found();
    }
    match format {
        "json" => {
            let values = records
                .iter()
                .zip(headers.iter())
                .map(|(record, header)| header_json(record, header))
                .collect::<Vec<_>>();
            json_response(Ok(Value::from(values)))
        }
        "hex" => {
            let body = headers
                .iter()
                .map(|header| serialize(header).to_lower_hex_string())
                .collect::<String>();
            text_response("text/plain", body.into_bytes())
        }
        "bin" => binary_response(
            "application/octet-stream",
            &headers.iter().fold(Vec::new(), |mut body, header| {
                body.extend(serialize(header));
                body
            }),
        ),
        _ => not_found(),
    }
}

fn header_records(ctx: &Context, hash: Hash256, count: u32) -> Vec<BlockRecord> {
    let Some(start) = ctx.block_by_hash(hash) else {
        return Vec::new();
    };
    let mut records = Vec::with_capacity(usize::try_from(count).unwrap_or(usize::MAX));
    let active_hash = ctx.block_by_height(start.height).map(|record| record.hash);
    if active_hash != Some(hash) {
        records.push(start);
        return records;
    }
    for height in start.height..=start.height.saturating_add(count.saturating_sub(1)) {
        let Some(record) = ctx.block_by_height(height) else {
            break;
        };
        records.push(record);
    }
    records
}

fn parse_count(query: &str) -> Result<u32, Response> {
    if query.is_empty() {
        return Ok(DEFAULT_HEADER_COUNT);
    }
    let Some(value) = query.strip_prefix("count=") else {
        return Err(bad_request("invalid count"));
    };
    let Ok(value) = value.parse::<u32>() else {
        return Err(bad_request("invalid count"));
    };
    if value == 0 {
        return Err(bad_request("count must be positive"));
    }
    Ok(value.min(MAX_HEADER_COUNT))
}

fn decode_header(record: &BlockRecord) -> Option<Header> {
    let bytes = Vec::<u8>::from_hex(&record.header_hex).ok()?;
    bitcoin::consensus::encode::deserialize(&bytes).ok()
}

fn header_json(record: &BlockRecord, header: &Header) -> Value {
    json!({
        "hash": record.hash.to_string_be(),
        "height": record.height,
        "version": header.version.to_consensus(),
        "previousblockhash": if record.height == 0 { None::<String> } else { Some(header.prev_blockhash.to_string()) },
        "merkleroot": header.merkle_root.to_string(),
        "time": header.time,
        "bits": format!("{:08x}", header.bits.to_consensus()),
        "nonce": header.nonce,
    })
}

fn json_response(result: Result<Value, RpcError>) -> Response {
    match result {
        Ok(value) => {
            let body = sonic_rs::to_string(&value).unwrap_or_else(|_| "null".to_owned());
            text_response("application/json", body.into_bytes())
        }
        Err(error) => match error {
            RpcError::InvalidParams(message) => bad_request(message),
            RpcError::NotFound(message) => not_found_with(message),
            _ => Response {
                status: 500,
                reason: "Internal Server Error",
                content_type: "text/plain",
                body: error.to_string().into_bytes(),
            },
        },
    }
}

fn text_response(content_type: &'static str, body: Vec<u8>) -> Response {
    Response {
        status: 200,
        reason: "OK",
        content_type,
        body,
    }
}

fn binary_response(content_type: &'static str, body: &[u8]) -> Response {
    text_response(content_type, body.to_vec())
}

fn bad_request(message: &'static str) -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}

fn not_found() -> Response {
    not_found_with("not found")
}

/// Constructs the Core-style response for an unsupported HTTP path.
#[must_use]
pub(crate) fn not_found_response() -> Response {
    not_found()
}

fn not_found_with(message: &'static str) -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode, block::Version};
    use sonic_rs::JsonValueTrait;

    #[test]
    fn disabled_rest_is_not_found() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/chaininfo.json", "", false);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn chaininfo_json_uses_enforcer_field_names() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/chaininfo.json", "", true);
        assert_eq!(response.status, 200);
        let value: Value = sonic_rs::from_slice(&response.body).expect("chaininfo JSON");
        for field in ["chain", "blocks", "headers", "bestblockhash"] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
    }

    #[test]
    fn route_rejects_unknown_formats_and_bad_hashes() {
        let ctx = Arc::new(Context::new());
        assert_eq!(
            route(
                &ctx,
                "/rest/headers/0000000000000000000000000000000000000000000000000000000000000000.txt",
                "",
                true
            )
            .status,
            404
        );
        assert_eq!(
            route(&ctx, "/rest/headers/not-a-hash.json", "", true).status,
            400
        );
    }

    #[test]
    fn count_defaults_and_clamps() {
        assert_eq!(parse_count("").expect("default"), 5);
        assert_eq!(parse_count("count=999999").expect("clamped"), 2_000);
        assert_eq!(parse_count("count=0").expect_err("zero count").status, 400);
        assert_eq!(parse_count("count=bad").expect_err("bad count").status, 400);
        assert_eq!(parse_count("limit=5").expect_err("bad query").status, 400);
    }

    #[test]
    fn headers_json_returns_ordered_active_chain_headers() {
        use bitcoin::hashes::Hash as _;
        use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode, block::Version};

        let ctx = Arc::new(Context::new());
        let bits = CompactTarget::from_consensus(0x1d00_ffff);
        let genesis_header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits,
            nonce: 1,
        };
        let genesis = Block {
            header: genesis_header,
            txdata: Vec::new(),
        };
        let child_header = Header {
            version: Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 2,
            bits,
            nonce: 2,
        };
        let child = Block {
            header: child_header,
            txdata: Vec::new(),
        };
        let tip_header = Header {
            version: Version::ONE,
            prev_blockhash: child.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 3,
            bits,
            nonce: 3,
        };
        let tip = Block {
            header: tip_header,
            txdata: Vec::new(),
        };
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        ctx.add_block(BlockRecord::from_block(1, &child));
        ctx.add_block(BlockRecord::from_block(2, &tip));

        let path = format!("/rest/headers/{}.json", child.block_hash());
        let response = route(&ctx, &path, "count=2", true);
        assert_eq!(response.status, 200);
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].get("height").and_then(Value::as_u64), Some(1));
        assert_eq!(values[1].get("height").and_then(Value::as_u64), Some(2));
        let child_hash = child.block_hash().to_string();
        assert_eq!(
            values[0].get("hash").and_then(Value::as_str),
            Some(child_hash.as_str())
        );
        let bits_text = values[0].get("bits").and_then(Value::as_str).expect("bits");
        assert_eq!(
            CompactTarget::from_unprefixed_hex(bits_text).expect("bits round-trip"),
            bits
        );
    }

    #[test]
    fn header_json_uses_enforcer_field_names() {
        let record = BlockRecord {
            hash: Hash256::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .expect("hash"),
            height: 1,
            block_hex: String::new(),
            body_size: 0,
            header_hex: String::new(),
            tx_count: 0,
            time: 123,
        };
        let header = Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 123,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 7,
        };
        let value = header_json(&record, &header);
        for field in [
            "hash",
            "height",
            "version",
            "previousblockhash",
            "merkleroot",
            "time",
            "bits",
            "nonce",
        ] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
        assert_eq!(value.get("bits").and_then(Value::as_str), Some("1d00ffff"));
    }
}
