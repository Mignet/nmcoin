package com.v5ent.nmcoin.entity;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.v5ent.nmcoin.NmCoin;
import com.v5ent.nmcoin.utils.KeyUtils;

public class Wallet {
	private static final Logger LOGGER = LoggerFactory.getLogger(Wallet.class);
	public PrivateKey privateKey;
	public PublicKey publicKey;
	public String address;
	
	public HashMap<String,TransactionOutput> UTXOs = new HashMap<String,TransactionOutput>();
	/**
	 * 默认构造钱包
	 */
	public Wallet() {
		generateKeyPair();
	}
	/***
	 * 根据用户私钥构造钱包
	 * @param privateKeyFile
	 */
	public Wallet(String privateKeyFile){
		try {
			this.privateKey = KeyUtils.loadPEMPrivateKey(
					FileUtils.readFileToString(new File(privateKeyFile), StandardCharsets.UTF_8), "ECDSA", "BC");
			this.publicKey = getPublicKeyFromPrivateKey(privateKey);
			this.address = getAddressFromPubKey(publicKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static PublicKey getPublicKeyFromPrivateKey(PrivateKey privateKey) throws GeneralSecurityException{
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
	    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

	    ECPoint Q = ecSpec.getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey).getD());

	    ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
	    PublicKey publicKeyGenerated = keyFactory.generatePublic(pubSpec);
	    return publicKeyGenerated;
	}
    /**
     * 根据公钥生成地址
     * @param pubkey
     * @return
     */
	public static String getAddressFromPubKey(PublicKey pubkey){
		ECPublicKey epub = (ECPublicKey)pubkey;
		ECPoint pt = epub.getQ();
		return "0x"+Hex.toHexString(computeAddress(pt.getEncoded(false)));
	}
	 /**
     * 根据公钥string生成地址
     * @param pubkey
     * @return
     */
	public static String getAddressFromPubKeyStr(String pubkey){
		return getAddressFromPubKey(convertPubKeyStrToKey(pubkey));
	}
	
	/***
	 * convert pubkeystr to pubkey
	 * @param pubkey
	 * @return
	 */
	public static PublicKey convertPubKeyStrToKey(String pubkey){
		byte[] publicBytes = Base64.decode(pubkey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory;
		PublicKey pubKey = null;
		try {
			keyFactory = KeyFactory.getInstance("ECDSA","BC");
			pubKey = keyFactory.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return pubKey;
	}
	
	public String getPubKeyStr(){
		
		return Base64.toBase64String(this.publicKey.getEncoded());
	}
	
	public static byte[] sha3(byte[] input) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("ETH-KECCAK-256", "BC");
			digest.update(input);
			return digest.digest();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}
	/**
     * Calculates RIGTMOST160(SHA3(input)). This is used in address
     * calculations. *
     * 
     * @param input
     *            - data
     * @return - 20 right bytes of the hash keccak of the data
     */
    public static byte[] sha3omit12(byte[] input) {
        byte[] hash = sha3(input);
        return Arrays.copyOfRange(hash, 12, hash.length);
    }
    
    /**
     * Compute an address from an encoded public key.
     *
     * @param pubBytes an encoded (uncompressed) public key
     * @return 20-byte address
     */
    public static byte[] computeAddress(byte[] pubBytes) {
        return sha3omit12(
        		Arrays.copyOfRange(pubBytes, 1, pubBytes.length));
    }
	 
	public void generateKeyPair() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA","BC");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
			// Initialize the key generator and generate a KeyPair
			keyGen.initialize(ecSpec,random); //256 
	        KeyPair keyPair = keyGen.generateKeyPair();
	        // Set the public and private keys from the keyPair
	        privateKey = keyPair.getPrivate();
	        publicKey = keyPair.getPublic();
	        address = getAddressFromPubKey(publicKey);
		}catch(Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public float getBalance() {
		float total = 0;	
        for (Map.Entry<String, TransactionOutput> item: NmCoin.UTXOs.entrySet()){
        	TransactionOutput UTXO = item.getValue();
            if(UTXO.isMine(address)) { //if output belongs to me ( if coins belong to me )
            	UTXOs.put(UTXO.id,UTXO); //add it to our list of unspent transactions.
            	total += UTXO.value ; 
            }
        }  
		return total;
	}
	
	/**
	 * 转账
	 * @param recipient 收款人地址
	 * @param value 转账金额
	 * @return
	 */
	public Transaction sendFunds(String recipient,float value ) {
		if(getBalance() < value) {
			LOGGER.info("#Not Enough funds to send transaction. Transaction Discarded.");
			return null;
		}
		ArrayList<TransactionInput> inputs = new ArrayList<TransactionInput>();
		
		float total = 0;
		for (Map.Entry<String, TransactionOutput> item: UTXOs.entrySet()){
			TransactionOutput UTXO = item.getValue();
			total += UTXO.value;
			inputs.add(new TransactionInput(UTXO.id));
			if(total > value){
				break;
			}
		}
		
		Transaction newTransaction = new Transaction(getPubKeyStr(), recipient , value, inputs);
		//私钥签名
		newTransaction.generateSignature(privateKey);
		
		for(TransactionInput input: inputs){
			UTXOs.remove(input.transactionOutputId);
		}
		
		return newTransaction;
	}
	
}


