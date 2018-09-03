package pdf;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;

import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfSignatureAppearance.RenderingMode;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
public class CipherPdf {
 
    /*
     * pdf数字签名
     * @param 印章文件路径
     * @param 需要签章的pdf文件路径
     * @param 签章结束的pdf文件路径
     * @param 证书连
     * @param 签名私钥
     * @param 摘要算法名称
     * @param 密钥算法提供者,可以为null
     * @param 数字签名格式
     * @param 签名原因,显示在pdf签名中属性
     * @param 签名地点,显示在pdf签名中属性 
     * */
    
    public void sign(String imgPath,String src, String dest, Certificate[] cert 
            , PrivateKey privateKey,Rectangle rectangle,String sginName ,String digestAlgorithm, String provider
            , CryptoStandard cryptoStandard, String reason, String location)
                    throws GeneralSecurityException, IOException, DocumentException {
        PdfReader reader = new PdfReader(src);
        //目标文件输出流
        FileOutputStream os = new FileOutputStream(dest);
        //创建签章工具PdfStamper ，最后一个boolean参数 
        //false的话，pdf文件只允许被签名一次，多次签名，最后一次有效
        //true的话，pdf可以被追加签名，验签工具可以识别出每次签名之后文档是否被修改
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
        // 获取数字签章属性对象，设定数字签章的属性
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        //设置签名的位置，页码，签名域名称，多次追加签名的时候，签名预名称不能一样
        //签名的位置，是图章相对于pdf页面的位置坐标，原点为pdf页面左下角
        appearance.setVisibleSignature(rectangle, 1, sginName);
        //读取图章图片，这个image是itext包的image
        Image image = Image.getInstance(imgPath); 
        appearance.setSignatureGraphic(image); 
        appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        //设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
        appearance.setRenderingMode(RenderingMode.GRAPHIC);
        // 签名算法
        ExternalSignature signature = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, null);
        // 这里的itext提供了2个用于签名的接口，可以自己实现，后边着重说这个实现
        // 摘要算法
        ExternalDigest digest = new BouncyCastleDigest();
        // 调用itext签名方法完成pdf签章
        MakeSignature.signDetached(appearance, digest, signature, cert, null, null, null, 0, cryptoStandard);
       
    }
}
