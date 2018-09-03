package com.security.cipher.sm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

public class SM2Utils 
{
	public static byte[] encrypt(byte[] publicKey, byte[] data)
	{
		if (publicKey == null || publicKey.length == 0)
		{
			return null;
		}
		
		if (data == null || data.length == 0)
		{
			return null;
		}
		
		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);

        byte[] formatedPubKey;
        if (publicKey.length == 64){
            //添加一字节标识，用于ECPoint解析
            formatedPubKey = new byte[65];
            formatedPubKey[0] = 0x04;
            System.arraycopy(publicKey,0,formatedPubKey,1,publicKey.length);
        }
        else
            formatedPubKey = publicKey;
		
		Cipher cipher = new Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(formatedPubKey);
		
		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		
		DERInteger x = new DERInteger(c1.getX().toBigInteger());
		DERInteger y = new DERInteger(c1.getY().toBigInteger());
		DEROctetString derDig = new DEROctetString(c3);
		DEROctetString derEnc = new DEROctetString(source);
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(x);
		v.add(y);
		v.add(derDig);
		v.add(derEnc);
		DERSequence seq = new DERSequence(v);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DEROutputStream dos = new DEROutputStream(bos);
        try {
            dos.writeObject(seq);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
	
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData)
	{
		if (privateKey == null || privateKey.length == 0)
		{
			return null;
		}
		
		if (encryptedData == null || encryptedData.length == 0)
		{
			return null;
		}
		
		byte[] enc = new byte[encryptedData.length];
		System.arraycopy(encryptedData, 0, enc, 0, encryptedData.length);
		
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);
		
		ByteArrayInputStream bis = new ByteArrayInputStream(enc);
		ASN1InputStream dis = new ASN1InputStream(bis);
        try {
            ASN1Primitive derObj = dis.readObject();
            ASN1Sequence asn1 = (ASN1Sequence) derObj;
            DERInteger x = (DERInteger) asn1.getObjectAt(0);
            DERInteger y = (DERInteger) asn1.getObjectAt(1);
            ECPoint c1 = sm2.ecc_curve.createPoint(x.getValue(), y.getValue(), true);

            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            DEROctetString data = (DEROctetString) asn1.getObjectAt(3);
            enc = data.getOctets();
            cipher.Decrypt(enc);
            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);
            return enc;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用默认ID计算
     * @param privateKey
     * @param useId
     * @param sourceData
     * @return
     */
	public static byte[] sign(byte[] userId, byte[] privateKey, byte[] sourceData)
	{
		if (privateKey == null || privateKey.length == 0)
		{
			return null;
		}
		
		if (sourceData == null || sourceData.length == 0)
		{
			return null;
		}
		
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(privateKey);
		System.out.println("userD: " + userD.toString(16));
		System.out.println("");
		
		ECPoint userKey = sm2.ecc_point_g.multiply(userD);
		
		SM3Digest sm3 = new SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);
		
		sm3.update(z, 0, z.length);
	    sm3.update(sourceData, 0, sourceData.length);
	    byte[] md = new byte[32];
	    sm3.doFinal(md, 0);
	    
	    SM2Result sm2Result = new SM2Result();
	    sm2.sm2Sign(md, userD, userKey, sm2Result);
	    
	    DERInteger d_r = new DERInteger(sm2Result.r);
	    DERInteger d_s = new DERInteger(sm2Result.s);
	    ASN1EncodableVector v2 = new ASN1EncodableVector();
	    v2.add(d_r);
	    v2.add(d_s);
	    DERSequence sign = new DERSequence(v2);
        try {
			return sign.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

    /**
     * 使用默认id计算
     * @param publicKey
     * @param sourceData
     * @param userId
     * @param signData
     * @return
     */
	@SuppressWarnings("unchecked")
	public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData)
	{
		if (publicKey == null || publicKey.length == 0)
		{
			return false;
		}
		
		if (sourceData == null || sourceData.length == 0)
		{
			return false;
		}

        byte[] formatedPubKey;
        if (publicKey.length == 64){
            //添加一字节标识，用于ECPoint解析
            formatedPubKey = new byte[65];
            formatedPubKey[0] = 0x04;
            System.arraycopy(publicKey,0,formatedPubKey,1,publicKey.length);
        }
        else
            formatedPubKey = publicKey;
		
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(formatedPubKey);

		SM3Digest sm3 = new SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);
		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
	    byte[] md = new byte[32];
	    sm3.doFinal(md, 0);
		
	    ByteArrayInputStream bis = new ByteArrayInputStream(signData);
	    ASN1InputStream dis = new ASN1InputStream(bis);
		SM2Result sm2Result = null;
		try {
			ASN1Primitive derObj = dis.readObject();
			Enumeration<DERInteger> e = ((ASN1Sequence) derObj).getObjects();
			BigInteger r = ((DERInteger)e.nextElement()).getValue();
			BigInteger s = ((DERInteger)e.nextElement()).getValue();
			sm2Result = new SM2Result();
			sm2Result.r = r;
			sm2Result.s = s;
			sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
			return sm2Result.r.equals(sm2Result.R);
		} catch (IOException e1) {
			e1.printStackTrace();
            return false;
        }
	}


	
	public static void main(String[] args) throws Exception 
	{
		byte[] b = null;
		try {
			//从文件地址中读取内容到程序中
			//1、建立连接
			InputStream is = new FileInputStream("/Users/apple/Downloads/test.p12");
			KeyStore keyStore ;
			is.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// 国密规范测试私钥
		String prik = "111111";

		String prikS = new String(Base64.encode(Util.hexToByte(prik)));
		
		System.out.println("解密: ");
		String plainText = new String(SM2Utils.decrypt(Base64.decode(prikS.getBytes()), b));
		System.out.println(plainText);
	}

}
