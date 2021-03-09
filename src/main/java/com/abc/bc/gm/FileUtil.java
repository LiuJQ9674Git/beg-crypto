package com.abc.bc.gm;

import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.xml.bind.DatatypeConverter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;

public class FileUtil {
    private static final String BEGIN_PUBLIC_KEY="-----BEGIN CERTIFICATE-----\n";
    private static final String END_PUBLIC_KEY="-----END CERTIFICATE-----";
    private static final String BEGIN_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n";
    private static final String END_PRIVATE_KEY="\n-----END PRIVATE KEY-----";

    public static void writeFile(String filePath, byte[] data) throws IOException {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(filePath, "rw");
            raf.write(data);
        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }

    public static void writePublicKey(String filePath, byte[] data) throws IOException {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(filePath, "rw");
            try {
                byte[] base=encryptBASE64(data).getBytes();
                raf.writeBytes(BEGIN_PUBLIC_KEY);
                raf.write(base);
                raf.writeBytes(END_PUBLIC_KEY);
            } catch (Exception e) {
                e.printStackTrace();

            }

        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }

    public static void writePrivateKey(String filePath, byte[] data) throws IOException {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(filePath, "rw");
            byte[] bytes=Base64.encode(data);
            StringBuilder sb = new StringBuilder(300);
            raf.write(BEGIN_PRIVATE_KEY.getBytes());
            int LEN = bytes.length;
            for (int ix = 0; ix < LEN; ++ix) {
                raf.write(bytes[ix]);
                if ((ix + 1) % 64 == 0) {
                    raf.write('\n');
                }
            }
            raf.write(END_PRIVATE_KEY.getBytes());
        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }

    public static byte[] readPrivateKey(String filePath) throws IOException {
        RandomAccessFile raf = null;
        byte[] data;
        try {
            raf = new RandomAccessFile(filePath, "r");
            raf.readLine();
            int dataL= (int) raf.length()-BEGIN_PRIVATE_KEY.length()-END_PRIVATE_KEY.length();
            data = new byte[(int)dataL];
            raf.read(data);
            byte[] bytes=Base64.decode(data);
            return bytes;
        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }

    public static byte[] readFile(String filePath) throws IOException {
        RandomAccessFile raf = null;
        byte[] data;
        try {
            raf = new RandomAccessFile(filePath, "r");
            data = new byte[(int) raf.length()];
            raf.read(data);
            return data;
        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }

    public static byte[] readKey(String filePath) throws IOException {
        RandomAccessFile raf = null;
        byte[] data;
        try {
            raf = new RandomAccessFile(filePath, "r");
            data = new byte[(int) raf.length()];
            raf.readLine();
            raf.read(data);
            try {
                return decryptBASE64(new String(data));
            } catch (Exception e) {
                if (raf != null) {
                    raf.close();
                }
                return null;
            }
        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }


    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    public static void savePrivateKey(String keyFileName,byte[] data) throws IOException {
        // 保存private key
        try {
            FileOutputStream keyOut = new FileOutputStream(keyFileName);
            StringBuilder sb = new StringBuilder(300);
            sb.append("-----BEGIN PRIVATE KEY-----\n");
            String priKey = DatatypeConverter.printBase64Binary(data);
            // 每64个字符输出一个换行
            int LEN = priKey.length();
            for (int ix = 0; ix < LEN; ++ix) {
                sb.append(priKey.charAt(ix));

                if ((ix + 1) % 64 == 0) {
                    sb.append('\n');
                }
            }

            sb.append("\n-----END PRIVATE KEY-----\n");
            keyOut.write(sb.toString().getBytes());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
