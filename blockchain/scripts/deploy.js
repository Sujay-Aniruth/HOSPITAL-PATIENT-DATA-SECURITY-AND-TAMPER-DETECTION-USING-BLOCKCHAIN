const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("=================================================");
  console.log(" Deploying HospitalRecordIntegrity Smart Contract");
  console.log("=================================================");

  const [deployer] = await hre.ethers.getSigners();
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`Deploying from account: ${deployer.address}`);
  console.log(`Account balance: ${hre.ethers.formatEther(balance)} ETH`);

  const HospitalRecordIntegrity = await hre.ethers.getContractFactory("HospitalRecordIntegrity");
  const contract = await HospitalRecordIntegrity.deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  const network = await hre.ethers.provider.getNetwork();
  console.log(`Contract deployed successfully to: ${contractAddress}`);
  console.log(`Chain ID: ${network.chainId.toString()}`);

  // Load contract artifact for ABI
  const artifactPath = path.join(
    __dirname,
    "../artifacts/contracts/HospitalRecordIntegrity.sol/HospitalRecordIntegrity.json"
  );
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));

  const deploymentInfo = {
    address: contractAddress,
    chainId: Number(network.chainId),
    networkName: hre.network.name,
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
    abi: artifact.abi,
  };

  // Save to blockchain/deployed-contract.json
  const deployJsonPath = path.join(__dirname, "../deployed-contract.json");
  fs.writeFileSync(deployJsonPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`Saved deployment info to: ${deployJsonPath}`);

  // Save to app/config/contract.json for PHP backend
  const phpConfigPath = path.join(__dirname, "../../app/config/contract.json");
  fs.writeFileSync(phpConfigPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`Saved PHP contract config to: ${phpConfigPath}`);

  // Update .env file with contract address
  const envPath = path.join(__dirname, "../../.env");
  if (fs.existsSync(envPath)) {
    let envContent = fs.readFileSync(envPath, "utf8");
    if (envContent.includes("CONTRACT_ADDRESS=")) {
      envContent = envContent.replace(
        /CONTRACT_ADDRESS=.*/,
        `CONTRACT_ADDRESS=${contractAddress}`
      );
    } else {
      envContent += `\nCONTRACT_ADDRESS=${contractAddress}\n`;
    }
    fs.writeFileSync(envPath, envContent);
    console.log(`Updated .env with CONTRACT_ADDRESS=${contractAddress}`);
  }

  console.log("=================================================");
  console.log(" Deployment Completed Successfully");
  console.log("=================================================");
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});
