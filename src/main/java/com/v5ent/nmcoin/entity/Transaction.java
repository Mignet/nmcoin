package com.v5ent.nmcoin.entity;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.v5ent.nmcoin.NmCoin;
import com.v5ent.nmcoin.utils.CommonUtils;

public class Transaction {
	private static final Logger LOGGER = LoggerFactory.getLogger(Transaction.class);
	public String transactionId; //Contains a hash of transaction*
	/**发送者公钥 */
	public String sender; //Senders address/public key.
	/**接受者地址*/
	public String reciepient; //Recipients address/public key.
	public float value; //Contains the amount we wish to send to the recipient.
	public String signature; //This is to prevent anybody else from spending funds in our wallet.
	
	public List<TransactionInput> inputs = new ArrayList<TransactionInput>();
	public List<TransactionOutput> outputs = new ArrayList<TransactionOutput>();
	
	private static int sequence = 0; //A rough count of how many transactions have been generated 
	
	// Constructor: 
	public Transaction(String from, String to, float value,  List<TransactionInput> inputs) {
		this.sender = from;
		this.reciepient = to;
		this.value = value;
		this.inputs = inputs;
	}
	
	public boolean processTransaction() {
		
		if(verifySignature() == false) {
			LOGGER.info("#Transaction Signature failed to verify");
			return false;
		}
				
		//Gathers transaction inputs (Making sure they are unspent):
		for(TransactionInput i : inputs) {
			i.UTXO = NmCoin.UTXOs.get(i.transactionOutputId);
		}

		//Checks if transaction is valid:
		if(getInputsValue() < NmCoin.minimumTransaction) {
			LOGGER.info("Transaction Inputs too small: " + getInputsValue());
			LOGGER.info("Please enter the amount greater than " + NmCoin.minimumTransaction);
			return false;
		}
		
		//Generate transaction outputs:
		float leftOver = getInputsValue() - value; //get value of inputs then the left over change:
		transactionId = calulateHash();
		outputs.add(new TransactionOutput( this.reciepient, value,transactionId)); //send value to recipient
		outputs.add(new TransactionOutput( Wallet.getAddressFromPubKeyStr(this.sender), leftOver,transactionId)); //send the left over 'change' back to sender		
				
		//Add outputs to Unspent list
		for(TransactionOutput o : outputs) {
			NmCoin.UTXOs.put(o.id , o);
		}
		
		//Remove transaction inputs from UTXO lists as spent:
		for(TransactionInput i : inputs) {
			if(i.UTXO == null) continue; //if Transaction can't be found skip it 
			NmCoin.UTXOs.remove(i.UTXO.id);
		}
		
		return true;
	}
	
	public float getInputsValue() {
		float total = 0;
		for(TransactionInput i : inputs) {
			if(i.UTXO == null){
				continue; //if Transaction can't be found skip it, This behavior may not be optimal.
			}
			total += i.UTXO.value;
		}
		return total;
	}
	
	public void generateSignature(PrivateKey privateKey) {
		String data = sender + reciepient + Float.toString(value)	;
		signature = Hex.toHexString(CommonUtils.applyECDSASig(privateKey,data));		
	}
	
	public boolean verifySignature() {
		String data = sender + reciepient + Float.toString(value);
		return CommonUtils.verifyECDSASig(Wallet.convertPubKeyStrToKey(sender), data, Hex.decode(signature));
	}
	
	public float getOutputsValue() {
		float total = 0;
		for(TransactionOutput o : outputs) {
			total += o.value;
		}
		return total;
	}
	
	private String calulateHash() {
		sequence++; //increase the sequence to avoid 2 identical transactions having the same hash
		return CommonUtils.applySha256(
				sender +
				reciepient +
				Float.toString(value) + sequence
				);
	}
}
