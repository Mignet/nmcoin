package com.v5ent.nmcoin;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.v5ent.nmcoin.entity.Block;
import com.v5ent.nmcoin.entity.Transaction;
import com.v5ent.nmcoin.entity.TransactionInput;
import com.v5ent.nmcoin.entity.TransactionOutput;
import com.v5ent.nmcoin.entity.Wallet;
import com.v5ent.nmcoin.network.PeerNetwork;
import com.v5ent.nmcoin.network.PeerThread;
import com.v5ent.nmcoin.network.RpcServer;
import com.v5ent.nmcoin.network.RpcThread;
import com.v5ent.nmcoin.utils.CommonUtils;
import com.v5ent.nmcoin.utils.KeyUtils;

/**
 * 结点
 * 
 * @author Mignet
 *
 */
public class NmCoin {
	private static final Logger LOGGER = LoggerFactory.getLogger(NmCoin.class);

	/** 本地存储的区块链 */
	private static List<Block> blockChain = new ArrayList<Block>();
	// 未打包的交易区块
	private static Block unpackBlock = null;
	public static Map<String, TransactionOutput> UTXOs = new HashMap<String, TransactionOutput>();
	/** global 初始难度 */
	public static int difficulty = 3;
	/** 最小交易额 */
	public static float minimumTransaction = 0.001f;
	/** 当前钱包 */
	private static Wallet currWallet;
	private static String walletAddressForTest = "0xd866184068dc3ea59ea218050e094d7513c6d479";
	private static Transaction genesisTransaction;
	private static final String VERSION = "0.1";

	public static void main(String[] args) throws IOException, InterruptedException {
		final Gson gson = new GsonBuilder().create();
		final Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();
		int port = 8015;
		LOGGER.info("Starting peer network...  ");
		PeerNetwork peerNetwork = new PeerNetwork(port);
		peerNetwork.start();
		LOGGER.info("[  Node is Started in port:"+port+"  ]");

		LOGGER.info("Starting RPC daemon...  ");
		RpcServer rpcAgent = new RpcServer(port+1);
		rpcAgent.start();
		LOGGER.info("[  RPC agent is Started in port:"+(port+1)+"  ]");
		
		ArrayList<String> peers = new ArrayList<String>();
		File peerFile = new File("peers.list");
		if (!peerFile.exists()) {
			String host = InetAddress.getLocalHost().toString();
			FileUtils.writeStringToFile(peerFile, host+":"+port,StandardCharsets.UTF_8,true);
		}else{
			for (String peer : FileUtils.readLines(peerFile,StandardCharsets.UTF_8)) {
				String[] addr = peer.split(":");
				if(CommonUtils.isLocal(addr[0])&&String.valueOf(port).equals(addr[1])){
					continue;
				}
				LOGGER.info("peer:"+peer);
				peers.add(peer);
				//raw ipv4
				peerNetwork.connect(addr[0], Integer.parseInt(addr[1]));
			}
		}

		File dataFile = new File("block.list");
		//Setup Bouncey castle as a Security Provider
		Provider p = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		p.put("MessageDigest.ETH-KECCAK-256", "com.v5ent.nmcoin.crypto.Keccak256");
		p.put("MessageDigest.ETH-KECCAK-512", "com.v5ent.nmcoin.crypto.Keccak512");
		Security.addProvider(p);
		
		//just for test
		File walletFile = new File("wallet.pem");
		if(walletFile.exists()){
			currWallet = new Wallet("wallet.pem");
		}else{
			currWallet = new Wallet();
			KeyUtils.savePrivateKeyAsPEM(currWallet.privateKey, "wallet.pem");
		}
		boolean valid = true;
		if (!dataFile.exists()) {
			// hard code genesisBlock
			//Create wallets for test:
			Wallet coinbase = new Wallet();
			//create genesis transaction, which sends 100 Coin to 0x222c1a98c6418b0463f731c2ccd26116aba96459: 
			genesisTransaction = new Transaction(coinbase.getPubKeyStr(), "0x222c1a98c6418b0463f731c2ccd26116aba96459", 100f, null);
			genesisTransaction.generateSignature(coinbase.privateKey);	 //manually sign the genesis transaction	
			genesisTransaction.transactionId = "0"; //manually set the transaction id
			genesisTransaction.outputs.add(new TransactionOutput(genesisTransaction.reciepient, genesisTransaction.value, genesisTransaction.transactionId)); //manually add the Transactions Output
			UTXOs.put(genesisTransaction.outputs.get(0).id, genesisTransaction.outputs.get(0)); //its important to store our first transaction in the UTXOs list.
			
			LOGGER.info("Creating and Mining Genesis block... ");
			//创世块
			Block genesisBlock = new Block("0");
			genesisBlock.setIndex(1);
			genesisBlock.setDifficulty(difficulty);
			genesisBlock.setTimestamp("2017-07-13 22:32:00");//my son's birthday
			genesisBlock.addTransaction(genesisTransaction);
			genesisBlock.setHash(genesisBlock.mineBlock());
			blockChain.add(genesisBlock);
			FileUtils.writeStringToFile(dataFile,gson.toJson(genesisBlock), StandardCharsets.UTF_8,true);
		}else{
			List<String> list = FileUtils.readLines(dataFile, StandardCharsets.UTF_8);
			genesisTransaction = gson.fromJson(list.get(0), Block.class).transactions.get(0);
			UTXOs.put(genesisTransaction.outputs.get(0).id, genesisTransaction.outputs.get(0));
			for(String line:list){
				Block b = gson.fromJson(line, Block.class);
				//遍历交易
				for(Transaction t:b.transactions){
					if(t.inputs==null){//basecoin
						continue;
					}
					for(TransactionInput input: t.inputs) {	
						TransactionOutput tempOutput = UTXOs.get(input.transactionOutputId);
						if(tempOutput == null) {
							LOGGER.error("#Referenced input on Transaction(" + t + ") is Missing");
							valid = false;
						}
						
						if(input.UTXO.value != tempOutput.value) {
							LOGGER.error("#Referenced input Transaction(" + t + ") value is Invalid");
							valid = false;
						}
						
						UTXOs.remove(input.transactionOutputId);
					}
					
					for(TransactionOutput output: t.outputs) {
						UTXOs.put(output.id, output);
					}
					if( !t.outputs.get(0).reciepient.equals(t.reciepient)) {
						LOGGER.error("#Transaction(" + gson.toJson(t) + ") output reciepient is not who it should be");
						valid = false;
					}
					if( !t.outputs.get(1).reciepient.equals(Wallet.getAddressFromPubKeyStr(t.sender))) {
						LOGGER.error("#Transaction(" + gson.toJson(t) + ") output 'change' is not sender.");
						valid = false;
					}
				}
				if(!valid){
					LOGGER.error("local block chain data invalid!!!");
					System.exit(-5);
				}
				blockChain.add(b);
			}
			//循环遍历区块链进行hash检查
			Block currentBlock; 
			Block previousBlock;
			for(int i=1; i < blockChain.size(); i++) {
				currentBlock = blockChain.get(i);
				previousBlock = blockChain.get(i-1);
				int difficulty = currentBlock.getDifficulty();
				String hashTarget = new String(new char[difficulty]).replace('\0', '0');
				if(!currentBlock.getHash().equals(currentBlock.calculateHash()) ){
					LOGGER.error("#Current Hashes not equal");
					valid = false;
				}
				if(!previousBlock.getHash().equals(currentBlock.getPrevHash()) ) {
					LOGGER.error("#Previous Hashes not equal");
					valid = false;
				}
				if(!currentBlock.getHash().substring( 0, difficulty).equals(hashTarget)) {
					LOGGER.error("#This block hasn't been mined");
					valid = false;
				}
			}
			if(!valid){
				LOGGER.error("local block chain data invalid!!!");
				System.exit(-5);
			}
		}
		//pretty print
		LOGGER.info(prettyGson.toJson(blockChain));
		TimeUnit.SECONDS.sleep(2);
		
		int bestHeight = blockChain.size();
		//建立socket连接后，给大家广播握手
		peerNetwork.broadcast("VERSION "+ bestHeight+" " + VERSION);

		/**
		 * p2p 通讯
		 */
		while (true) {
			//对新连接过的peer写入文件，下次启动直接连接
			for (String peer : peerNetwork.peers) {
				if (!peers.contains(peer)) {
					peers.add(peer);
					LOGGER.info("add peer to file:"+peer);
					FileUtils.writeStringToFile(peerFile, "\r\n"+peer,StandardCharsets.UTF_8,true);
				}
			}
			peerNetwork.peers.clear();

			// 处理通讯
			for (PeerThread pt : peerNetwork.peerThreads) {
				if (pt == null || pt.peerReader == null) {
					break;
				}
				List<String> dataList = pt.peerReader.readData();
				if (dataList == null) {
					LOGGER.info("Null return, retry.");
					System.exit(-5);
					break;
				}

				for (String data:dataList) {
					LOGGER.info("[p2p] COMMAND:: " + data);
					int flag = data.indexOf(' ');
					String cmd = flag >= 0 ? data.substring(0, flag) : data;
					String payload = flag >= 0 ? data.substring(flag + 1) : "";
					if (CommonUtils.isNotBlank(cmd)) {
						if ("VERACK".equalsIgnoreCase(cmd)) {
							// 对方确认知道了,并给我区块高度
							String[] parts = payload.split(" ");
							bestHeight = Integer.parseInt(parts[0]);
							//哈希暂时不校验
						} else if ("VERSION".equalsIgnoreCase(cmd)) {
							// 握手信息
							// 获取区块高度和版本号信息
							String[] parts = payload.split(" ");
							bestHeight = Integer.parseInt(parts[0]);
							//我方回复：区块高度以及没有打包的交易
							pt.peerWriter.write("VERACK " + blockChain.size() + " " + blockChain.get(blockChain.size() - 1).getHash());
							if(unpackBlock!=null){
								for(Transaction tx:unpackBlock.transactions){
									pt.peerWriter.write("TRANSACTION " + gson.toJson(tx));
								}
							}
						} else if ("BLOCK".equalsIgnoreCase(cmd)) {
							//把对方给的块存进链中
							Block newBlock = gson.fromJson(payload, Block.class);
							if (!blockChain.contains(newBlock)) {
								LOGGER.info("Attempting to add Block: " + payload);
								// 校验区块，如果成功，将其写入本地区块链
								if (Block.isBlockValid(newBlock, blockChain.get(blockChain.size() - 1))) {
									//遍历交易
									for(Transaction t:newBlock.transactions){
										if(t.inputs==null){//skip basecoin
											continue;
										}
										for(TransactionInput input: t.inputs) {	
											TransactionOutput tempOutput = UTXOs.get(input.transactionOutputId);
											if(tempOutput == null) {
												LOGGER.error("#Referenced input on Transaction(" + t + ") is Missing");
												valid = false;
											}
											
											if(input.UTXO.value != tempOutput.value) {
												LOGGER.error("#Referenced input Transaction(" + t + ") value is Invalid");
												valid = false;
											}
											
											UTXOs.remove(input.transactionOutputId);
										}
										
										for(TransactionOutput output: t.outputs) {
											UTXOs.put(output.id, output);
										}
										if( !t.outputs.get(0).reciepient.equals(t.reciepient)) {
											LOGGER.error("#Transaction(" + gson.toJson(t) + ") output reciepient is not who it should be");
											valid = false;
										}
										if( !t.outputs.get(1).reciepient.equals(Wallet.getAddressFromPubKeyStr(t.sender))) {
											LOGGER.error("#Transaction(" + gson.toJson(t) + ") output 'change' is not sender.");
											valid = false;
										}
									}
									if(!valid){
										LOGGER.error("local block chain data invalid!!!");
										System.exit(-5);
									}
									blockChain.add(newBlock);
									//未完成的区块
									unpackBlock = new Block(newBlock.getHash());
									LOGGER.info("Added block " + newBlock.getIndex() + " with hash: ["+ newBlock.getHash() + "]");
									FileUtils.writeStringToFile(dataFile,"\r\n"+gson.toJson(newBlock), StandardCharsets.UTF_8,true);
									peerNetwork.broadcast("BLOCK " + payload);
								}
							}
						} else if ("GET_BLOCK".equalsIgnoreCase(cmd)) {
							//把对方请求的块给对方
							Block block = blockChain.get(Integer.parseInt(payload));
							if (block != null) {
								LOGGER.info("Sending block " + payload + " to peer");
								pt.peerWriter.write("BLOCK " + gson.toJson(block));
							}
						} else if ("TRANSACTION".equalsIgnoreCase(cmd)){
                            Transaction tx = gson.fromJson(payload, Transaction.class);
                            if(unpackBlock==null){
								unpackBlock = new Block(blockChain.get(blockChain.size()-1).getHash());
							}
                            if(!unpackBlock.transactions.contains(tx)){
                                if(tx.processTransaction()){
                                	unpackBlock.transactions.add(tx);
                                    LOGGER.info("New tx on network: ");
                                    LOGGER.info("     " + tx.value + " nmcoin(s) from " + tx.sender + " to " + tx.reciepient);
                                    LOGGER.info("Total nmcoin sent: "+ tx.reciepient);
                                    peerNetwork.broadcast("TRANSACTION " + payload);
                                } else {
                                    LOGGER.info("Invalid transaction: " + payload);
                                }
                            }
                        } else if ("ADDR".equalsIgnoreCase(cmd)) {
							// 对方发来地址，建立连接并保存
							if (!peers.contains(payload)) {
								String peerAddr = payload.substring(0, payload.indexOf(":"));
								int peerPort = Integer.parseInt(payload.substring(payload.indexOf(":") + 1));
								peerNetwork.connect(peerAddr, peerPort);
								peers.add(payload);
								PrintWriter out = new PrintWriter(peerFile);
								for (int k = 0; k < peers.size(); k++) {
									out.println(peers.get(k));
								}
								out.close();
							}
						} else if ("GET_ADDR".equalsIgnoreCase(cmd)) {
							//对方请求更多peer地址，随机给一个
							Random random = new Random();
							pt.peerWriter.write("ADDR " + peers.get(random.nextInt(peers.size())));
						} 
					}
				}
			}

			// ********************************
			// 		比较区块高度,同步区块
			// ********************************
			int localHeight = blockChain.size();
			if (bestHeight > localHeight) {
				LOGGER.info("Local chain height: " + localHeight+" Best chain Height: " + bestHeight);
				TimeUnit.MILLISECONDS.sleep(300);
				
				for (int i = localHeight; i < bestHeight; i++) {
					LOGGER.info("request get block[" + i + "]...");
					peerNetwork.broadcast("GET_BLOCK " + i);
				}
			}

			// ********************************
			// 处理RPC服务
			// ********************************
			for (RpcThread th:rpcAgent.rpcThreads) {
				String request = th.req;
				if (request != null) {
					String[] parts = request.split(" ");
					parts[0] = parts[0].toLowerCase();
					if ("getchain".equals(parts[0])) {
						String res = prettyGson.toJson(blockChain);
						th.res = res;
					} else if("getinfo".equals(parts[0])){
						LOGGER.info("Your address is: " + currWallet.address);
						th.res = "\nYour address is: " +currWallet.address;
					} else if("getbalance".equals(parts[0])){
						LOGGER.info("Your balance is: " + currWallet.getBalance());
						th.res = "\nYour balance is: " +currWallet.getBalance();
					} else if("send".equals(parts[0])){
						try {
							int vac = Integer.parseInt(parts[1]);
							if(parts.length>=3){
								if(KeyUtils.isValidAddress(parts[2])){
									walletAddressForTest = parts[2];
								}else{
									th.res = "invalid address";
								}
							}
							LOGGER.info("\nYou are Attempting to send funds ("+vac+") to "+walletAddressForTest+"...");
							Transaction tx = currWallet.sendFunds(walletAddressForTest, vac);
							if(unpackBlock==null){
								unpackBlock = new Block(blockChain.get(blockChain.size()-1).getHash());
							}
							if(tx!=null && unpackBlock.addTransaction(tx)){
								th.res = "Transaction write Success!";
								peerNetwork.broadcast("Transaction " + gson.toJson(tx));
							}else{
								th.res = "Transaction write failed! Maybe you haven't Enough funds";
							}
						}catch (Exception e) {
							th.res = "Syntax (no '<' or '>'): send <vac> <address>";
							LOGGER.error("invalid transaction command");
						}
					} else if ("mine".equals(parts[0])) {
						try {
							int difficulty = Integer.parseInt(parts[1]);
							// 挖矿打包新的块
							if(unpackBlock.transactions.isEmpty()){
								th.res = "Block write failed!No Transaction existed!";
							}else{
								Block newBlock = Block.generateBlock(blockChain.get(blockChain.size() - 1), difficulty,unpackBlock.transactions);
								if (Block.isBlockValid(newBlock, blockChain.get(blockChain.size() - 1))) {
									blockChain.add(newBlock);
									th.res = "Block write Success!";
									FileUtils.writeStringToFile(dataFile,"\r\n"+gson.toJson(newBlock), StandardCharsets.UTF_8,true);
									peerNetwork.broadcast("BLOCK " + gson.toJson(newBlock));
								} else {
									th.res = "RPC 500: Invalid vac Error";
								}
							}
						} catch (Exception e) {
							th.res = "Syntax (no '<' or '>'): mine <difficulty> - Mine <difficulty> with Block";
							LOGGER.error("invalid mine command");
						}
					} else {
						th.res = "Unknown command: \"" + parts[0] + "\" ";
					}
				}
			}

			// ****************
			// 循环结束
			// ****************
			TimeUnit.MILLISECONDS.sleep(100);
		}
	}

}
