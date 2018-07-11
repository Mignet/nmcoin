package com.v5ent.nmcoin.utils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Base64;

import com.v5ent.nmcoin.entity.Wallet;

public class KeyUtils {
	/**
	 * 保存公钥文件
	 * @param publicKey
	 * @param name
	 * @throws Exception
	 */
	public static void savePublicKeyAsPEM(PublicKey publicKey, String name) throws Exception {
		String content = Base64.toBase64String(publicKey.getEncoded());
		File file = new File(name);
		if (file.isFile() && file.exists())
			FileUtils.forceDelete(file);
		FileUtils.writeStringToFile(file, "-----BEGIN PUBLIC KEY-----\n", StandardCharsets.UTF_8, true);
		int i = 0;
		for (; i < (content.length() - (content.length() % 64)); i += 64) {
			FileUtils.writeStringToFile(file, content.substring(i, i + 64), StandardCharsets.UTF_8, true);
			FileUtils.writeStringToFile(file, "\n", StandardCharsets.UTF_8, true);
		}
		FileUtils.writeStringToFile(file, content.substring(i, content.length()), StandardCharsets.UTF_8, true);
		FileUtils.writeStringToFile(file, "\n", StandardCharsets.UTF_8, true);

		FileUtils.writeStringToFile(file, "-----END PUBLIC KEY-----", StandardCharsets.UTF_8, true);
	}
	/**
	 * 保存私钥文件
	 * @param privateKey
	 * @param name
	 * @throws IOException 
	 * @throws Exception
	 */
	public static void savePrivateKeyAsPEM(PrivateKey privateKey, String name) throws IOException  {
		String content = Base64.toBase64String(privateKey.getEncoded());
		File file = new File(name);
		if (file.isFile() && file.exists()) {
			FileUtils.forceDelete(file);
		}
		FileUtils.writeStringToFile(file, "-----BEGIN PRIVATE KEY-----\n", StandardCharsets.UTF_8);
		int i = 0;
		for (; i < (content.length() - (content.length() % 64)); i += 64) {
			FileUtils.writeStringToFile(file, content.substring(i, i + 64), StandardCharsets.UTF_8, true);
			FileUtils.writeStringToFile(file, "\n", StandardCharsets.UTF_8, true);
		}
		FileUtils.writeStringToFile(file, content.substring(i, content.length()), StandardCharsets.UTF_8, true);
		FileUtils.writeStringToFile(file, "\n", StandardCharsets.UTF_8, true);
		FileUtils.writeStringToFile(file, "-----END PRIVATE KEY-----", StandardCharsets.UTF_8, true);
	}

	/**
	 * 读取公钥
	 * 
	 * @param encodedKey
	 * @param algorithm
	 * @param provider
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException
	 */
	public static PublicKey loadPublicKey(byte[] encodedKey, String algorithm, String provider)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm, provider);
		return keyFactory.generatePublic(keySpec);
	}

	/***
	 * 读取私钥
	 * 
	 * @param encodedKey
	 * @param algorithm
	 * @param provider
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException
	 */
	public static PrivateKey loadPrivateKey(byte[] encodedKey, String algorithm, String provider)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm, provider);
		return keyFactory.generatePrivate(keySpec);
	}

	/**
	 * 读取PEM私钥
	 * 
	 * @param content
	 * @param algorithm
	 * @param provider
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey loadPEMPrivateKey(String content, String algorithm, String provider) throws Exception {
		String privateKeyPEM = content.replace("-----BEGIN PRIVATE KEY-----\n", "")
				.replace("-----END PRIVATE KEY-----", "").replace("\n", "");
		byte[] asBytes = Base64.decode(privateKeyPEM);
		return loadPrivateKey(asBytes, algorithm, provider);
	}

	/**
	 * 读取PEM公钥
	 * 
	 * @param content
	 * @param algorithm
	 * @param provider
	 * @return
	 * @throws Exception
	 */
	public static PublicKey loadPEMPublicKey(String content, String algorithm, String provider) throws Exception {
		String strPublicKey = content.replace("-----BEGIN PUBLIC KEY-----\n", "")
				.replace("-----END PUBLIC KEY-----", "").replace("\n", "");
		System.out.println(strPublicKey);
		byte[] asBytes = Base64.decode(strPublicKey);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(asBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm, provider);
		return (ECPublicKey) keyFactory.generatePublic(spec);
	}
	
	public static boolean isValidAddress(String addr)
	{
		String regex = "^0x[0-9a-f]{40}$";
		if(addr.matches(regex))
		{
			return true;
		}
		return false;
	}

	public static void main(String[] args) throws Exception {
		Provider p = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		p.put("MessageDigest.ETH-KECCAK-256", "com.v5ent.nmcoin.crypto.Keccak256");
		p.put("MessageDigest.ETH-KECCAK-512", "com.v5ent.nmcoin.crypto.Keccak512");
		Security.addProvider(p);

		/*Wallet w = new Wallet();
		savePrivateKeyAsPEM(w.privateKey, "privatekey.pem");
		savePublicKeyAsPEM(w.publicKey, "publickey.pem");
		ECPrivateKey epvt = (ECPrivateKey) w.privateKey;
		String sepvt = epvt.getS().toString(16);
		System.out.println("Private key[" + sepvt.length() + "]: " + sepvt);
		ECPublicKey epub = (ECPublicKey) w.publicKey;
		ECPoint pt = epub.getQ();
		System.out.println("Public Key: " + Hex.toHexString(pt.getEncoded(false)));
		System.out.println("Public compressed Key: " + Hex.toHexString(pt.getEncoded(true)));
		System.out.println(w.getPubKeyStr());
		PublicKey pk = Wallet.convertPubKeyStrToKey(w.getPubKeyStr());
		System.out.println(w.publicKey.equals(pk));
		System.out.println("Address: 0x" + Hex.toHexString(Wallet.computeAddress(pt.getEncoded(false))));
		PrivateKey privateKey = KeyUtil.loadPEMPrivateKey(
				FileUtils.readFileToString(new File("privatekey.pem"), StandardCharsets.UTF_8), "ECDSA", "BC");
		PublicKey publicKey = KeyUtil.loadPEMPublicKey(
				FileUtils.readFileToString(new File("publickey.pem"), StandardCharsets.UTF_8), "ECDSA", "BC");
		System.out.println(w.privateKey.equals(privateKey));
		System.out.println(w.publicKey.equals(publicKey));*/
		Wallet wallet = new Wallet("privatekey.pem");
		System.out.println(wallet.address);
	}

}
