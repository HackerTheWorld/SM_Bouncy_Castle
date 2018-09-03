package pdf;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Map;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;


public class Main {
	
    
    public static void main(String[] args){
    	 	 String keystore = "/Users/apple/Documents/tomatocc.p12";
    	 	 String imagepath = "/Users/apple/Downloads/tuzhang.jpg"; 
         String password = "wh3164335";
         String src = "/Users/apple/Downloads/softprogram.pdf";
         String dest = "/Users/apple/Downloads/sginsoftprogram.pdf";
         
         ReadP12Cert redP12Cert = new ReadP12Cert();
         Map<String,Object> keyStore = redP12Cert.SSLp12(keystore, password);
         Certificate[] cert = new Certificate[1];
        	 cert[0] = keyStore.get("cert") instanceof Certificate?(Certificate)keyStore.get("cert"):null;
         PrivateKey privateKey = keyStore.get("privateKey") instanceof PrivateKey?(PrivateKey)keyStore.get("privateKey"):null;
//			 pdf数字签名
    		 String reason = "test";
    		 String location = "changzhou";
    		 String digestAlgorithm = "panlingyun";
    		 Rectangle rectangle = new Rectangle(500,500,200,100);
    		 String name = "panlingyun";
    		 CryptoStandard  cryptoStandard = CryptoStandard.CMS;
         CipherPdf cipherPdf = new CipherPdf();
    		try {
    			
				cipherPdf.sign(imagepath, src, dest, cert, privateKey,rectangle,name,
						digestAlgorithm, null, cryptoStandard, reason, location);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
    }
    
}
