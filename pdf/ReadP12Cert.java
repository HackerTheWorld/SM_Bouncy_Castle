/**
 * ReadP12Cert.java
 * 版权所有(C) 2012 
 * 创建:cuiran 2012-07-31 15:50:53
 */
package pdf;
 
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
 
/**
 * TODO
 * @author cuiran
 * @version TODO
 */
public class ReadP12Cert {
 
	/**
	 * 解析p12文件
	 * @param 存放签名文件
	 * @param 签名文件密码
	 */
	public Map<String,Object> SSLp12(String keyStore_file,String keyStore_Password) {
		// TODO Auto-generated method stub
		Map<String,Object> returnMap = new HashMap<String,Object>();
        try
        {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            FileInputStream fis = new FileInputStream(keyStore_file);
            char[] nPassword = null;
            if ((keyStore_Password == null) || keyStore_Password.trim().equals(""))
	            {
	                nPassword = null;
	            }
            	else
	            {
	                nPassword = keyStore_Password.toCharArray();
	            }
            ks.load(fis, nPassword);
            fis.close();            
            returnMap.put("type", ks.getType());
            Enumeration enum1 = ks.aliases(); 
            String keyAlias = null; 
            if (enum1.hasMoreElements()) // we are readin just one certificate.
            {
                keyAlias = (String)enum1.nextElement();
                returnMap.put("alias", keyAlias);
            }
            returnMap.put("isentry", ks.isKeyEntry(keyAlias));
            PrivateKey prikey = (PrivateKey) ks.getKey(keyAlias, nPassword);
            returnMap.put("privateKey", prikey);
            Certificate cert = ks.getCertificate(keyAlias);
            	returnMap.put("cert", cert);
            PublicKey pubkey = cert.getPublicKey();
            	returnMap.put("publicKey", pubkey);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return returnMap;
	}
}
