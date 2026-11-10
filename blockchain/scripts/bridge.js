/**
 * Blockchain Bridge CLI
 * 
 * Provides an isolated execution bridge between PHP and EVM networks
 * for cryptographic transaction signing and contract interactions.
 * 
 * Usage:
 *   node bridge.js status
 *   node bridge.js store <recordType> <recordId> <version> <hash>
 *   node bridge.js get <recordType> <recordId> <version>
 *   node bridge.js list
 */

const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

function loadConfig() {
  const envPath = path.join(__dirname, "../../.env");
  const env = {};
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, "utf8").split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const idx = trimmed.indexOf("=");
      if (idx !== -1) {
        const key = trimmed.slice(0, idx).trim();
        let val = trimmed.slice(idx + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        env[key] = val;
      }
    }
  }

  const contractJsonPath = path.join(__dirname, "../deployed-contract.json");
  let contractInfo = null;
  if (fs.existsSync(contractJsonPath)) {
    contractInfo = JSON.parse(fs.readFileSync(contractJsonPath, "utf8"));
  }

  return {
    rpcUrl: env.RPC_URL || "http://127.0.0.1:8545",
    chainId: Number(env.CHAIN_ID || 31337),
    contractAddress: env.CONTRACT_ADDRESS || (contractInfo ? contractInfo.address : ""),
    signerKey: env.SIGNER_PRIVATE_KEY || "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    contractInfo,
  };
}

async function getContractInstance(config, withSigner = false) {
  const provider = new ethers.JsonRpcProvider(config.rpcUrl);
  if (!config.contractInfo || !config.contractAddress) {
    throw new Error("Contract address or ABI not found. Please deploy contract first.");
  }

  if (withSigner) {
    const wallet = new ethers.Wallet(config.signerKey, provider);
    return new ethers.Contract(config.contractAddress, config.contractInfo.abi, wallet);
  } else {
    return new ethers.Contract(config.contractAddress, config.contractInfo.abi, provider);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "status";
  const config = loadConfig();

  try {
    if (command === "status") {
      const provider = new ethers.JsonRpcProvider(config.rpcUrl);
      const network = await provider.getNetwork();
      const blockNumber = await provider.getBlockNumber();
      let contractDeployed = false;
      let totalAnchors = 0;

      if (config.contractAddress) {
        const code = await provider.getCode(config.contractAddress);
        contractDeployed = code !== "0x" && code !== "0x0";
        if (contractDeployed && config.contractInfo) {
          const contract = new ethers.Contract(config.contractAddress, config.contractInfo.abi, provider);
          try {
            totalAnchors = Number(await contract.totalAnchoredRecords());
          } catch (e) {
            totalAnchors = 0;
          }
        }
      }

      console.log(JSON.stringify({
        status: "success",
        connected: true,
        chainId: Number(network.chainId),
        latestBlock: blockNumber,
        contractAddress: config.contractAddress,
        contractDeployed,
        totalAnchoredRecords: totalAnchors,
      }));
      return;
    }

    if (command === "store") {
      const recordType = args[1];
      const recordId = parseInt(args[2], 10);
      const version = parseInt(args[3], 10);
      let hash = args[4];

      if (!recordType || isNaN(recordId) || isNaN(version) || !hash) {
        throw new Error("Missing parameters: node bridge.js store <recordType> <recordId> <version> <hash>");
      }

      if (!hash.startsWith("0x")) {
        hash = "0x" + hash;
      }

      const contract = await getContractInstance(config, true);
      const tx = await contract.storeRecordHash(recordType, recordId, version, hash);
      const receipt = await tx.wait();

      console.log(JSON.stringify({
        status: "success",
        recordType,
        recordId,
        version,
        hash,
        transactionHash: receipt.hash,
        blockNumber: Number(receipt.blockNumber),
        gasUsed: receipt.gasUsed.toString(),
      }));
      return;
    }

    if (command === "get") {
      const recordType = args[1];
      const recordId = parseInt(args[2], 10);
      const version = parseInt(args[3], 10);

      if (!recordType || isNaN(recordId) || isNaN(version)) {
        throw new Error("Missing parameters: node bridge.js get <recordType> <recordId> <version>");
      }

      const contract = await getContractInstance(config, false);
      const [hash, timestamp, anchoredBy, exists] = await contract.getRecordHash(recordType, recordId, version);

      console.log(JSON.stringify({
        status: "success",
        recordType,
        recordId,
        version,
        hash,
        timestamp: Number(timestamp),
        anchoredBy,
        exists,
      }));
      return;
    }

    if (command === "list") {
      const contract = await getContractInstance(config, false);
      const total = Number(await contract.totalAnchoredRecords());
      const list = [];

      for (let i = 0; i < total; i++) {
        const item = await contract.getRecordAtIndex(i);
        list.push({
          key: item[0],
          recordType: item[1],
          recordId: Number(item[2]),
          version: Number(item[3]),
          hash: item[4],
          timestamp: Number(item[5]),
          anchoredBy: item[6],
        });
      }

      console.log(JSON.stringify({
        status: "success",
        total,
        records: list,
      }));
      return;
    }

    throw new Error(`Unknown command: ${command}`);
  } catch (error) {
    console.error(JSON.stringify({
      status: "error",
      message: error.message || String(error),
    }));
    process.exit(1);
  }
}

main();
