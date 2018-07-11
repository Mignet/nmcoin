package com.v5ent.nmcoin.entity;

import com.v5ent.nmcoin.utils.CommonUtils;

public class TransactionOutput {
	public String id;
	public String reciepient; //also known as the new owner of these coins.
	public float value; //the amount of coins they own
	public String parentTransactionId; //the id of the transaction this output was created in
	
	//Constructor
	public TransactionOutput(String reciepient, float value, String parentTransactionId) {
		this.reciepient = reciepient;
		this.value = value;
		this.parentTransactionId = parentTransactionId;
		this.id = CommonUtils.applySha256(reciepient+Float.toString(value)+parentTransactionId);
	}
	
	//Check if coin belongs to you
	public boolean isMine(String address) {
		return address.equals(reciepient);
	}
	
}
