import { ethers } from "hardhat";

import type { FHEordle, FHEordleFactory } from "../../types";
import { getSigners } from "../signers";

export async function deployFHEordleFixture(): Promise<[FHEordle, FHEordleFactory]> {
  const signers = await getSigners();

  const contractFactory = await ethers.getContractFactory("FHEordle");
  const contract = await contractFactory.connect(signers.alice).deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();

  const contractFactoryFactoryFactory = await ethers.getContractFactory("FHEordleFactory");
  const contractFactoryFactory = await contractFactoryFactoryFactory.connect(signers.alice).deploy(contractAddress);
  await contractFactoryFactory.waitForDeployment();

  return [contract, contractFactoryFactory];
}
