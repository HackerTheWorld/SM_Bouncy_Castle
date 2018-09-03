package pdf;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import com.itextpdf.text.pdf.security.ExternalSignature;
import com.security.cipher.sm.SM2Utils;

public class SM2sgin implements ExternalSignature{
	
	/** The private key object. */
    private PrivateKey pk;
    /** The encryption algorithm (obtained from the private key) */
    private String encryptionAlgorithm;
    /** The security provider */
    private String provider;
	
	public SM2sgin(PrivateKey pk,String provider){
		this.pk = pk;
		this.provider = provider;
		this.encryptionAlgorithm = pk.getAlgorithm();
	}
	
	@Override
	public String getHashAlgorithm() {
		// TODO Auto-generated method stub
		return "SHA-1";
	}

	@Override
	public String getEncryptionAlgorithm() {
		// TODO Auto-generated method stub
		return encryptionAlgorithm;
	}

	@Override
	public byte[] sign(byte[] message) throws GeneralSecurityException {
		// TODO Auto-generated method stub
		return SM2Utils.sign(provider.getBytes(), pk.getEncoded(), message);
		 
	}

}
