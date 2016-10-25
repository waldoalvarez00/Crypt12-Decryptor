import java.io.BufferedInputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.CipherInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.Serializable;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Provider;
import java.util.Arrays;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.*;


public class Decrypt
{
    private static final String FILE_BACKUP_KEY = "key";
    private static final String FILE_BACKUP_OUT = "msgstore.db";
    private static final String FILE_ENC = "msgstore.db.crypt12.enc";
    private static final byte[] BACKUP_CIPHER_HEADER;
    private static final byte[] BACKUP_CIPHER_HEADER_V1;
    private static final byte[] BACKUP_CIPHER_HEADER_V2;
    private static final int    HEADER_LENGTH = 2;
    private static final int    SERVER_SALT_LENGTH = 32;
    private static final int    GOOGLE_ID_SALT_LENGTH = 16;
    private static final int    ENCRYPTION_IV_LENGTH = 16;
    static{
        BACKUP_CIPHER_HEADER    = new byte[] { 0, 1 };
        BACKUP_CIPHER_HEADER_V1 = new byte[] { 0, 1 };
        BACKUP_CIPHER_HEADER_V2 = new byte[] { 0, 2 };

        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public static void main(String[] args) {
        InputStream inputstream;
        BackupCipher cipher = null;

        if (args.length < 1 || args.length != 2) {
            System.out.println("Usage: java -classpath \"lib/bc.jar:.\" Decrypt [crypt12File] [keyFile]");
            System.exit(0);
        }

        doesFileExists(args[0], args[1]);

        try {
            inputstream = new FileInputStream(args[0]);
            cipher = readBackupCipher(inputstream);
        } catch (IOException ex) {
            System.out.println("Error reading file\n");
        }
        BackupKey backupkey = getBackupKeyWithRandomizedIV(args[1]);

        byte[] iv = new byte[16];
        byte[] key = new byte[32];
        String keyVersion = null;

        keyVersion = cipher.keyVersion;
        iv = cipher.encryptionIv;
        key = backupkey.cipherKey;

        displayTitle();
        logToDisplay(iv, key, keyVersion);

        DecryptDB("msgstore.db.crypt12", iv, key);

        System.out.println("\n\nSuccess! msgstore.db generated!");
    }

    public static BackupCipher readBackupCipher(final InputStream inputStream) throws IOException {
        final byte[] header = new byte[Decrypt.BACKUP_CIPHER_HEADER.length];
        final byte[] serverSalt = new byte[32];
        final byte[] googleIdSalt = new byte[16];
        final byte[] encryptionIv = new byte[16];
        final byte[] array = new byte[1 + header.length + serverSalt.length + googleIdSalt.length + encryptionIv.length];
        inputStream.read(array);
        System.arraycopy(array, 0, header, 0, Decrypt.BACKUP_CIPHER_HEADER.length);
        final int n = 0 + Decrypt.BACKUP_CIPHER_HEADER.length;
        if (!Arrays.equals(header, Decrypt.BACKUP_CIPHER_HEADER_V2) && !Arrays.equals(header, Decrypt.BACKUP_CIPHER_HEADER_V1)) {
            System.out.println("Wrong header!\n");
            System.exit(0);
        }
        final int n2 = n + 1;
        final String keyVersion = String.valueOf((int)array[n]);
        final byte[][] array2 = { serverSalt, googleIdSalt, encryptionIv };
        final int length = array2.length;
        int i = 0;
        int n3 = n2;
        for (; i < length; ++i) {
            final byte[] array3 = array2[i];
            System.arraycopy(array, n3, array3, 0, array3.length);
            n3 += array3.length;
        }

        return new BackupCipher(header, keyVersion, serverSalt, googleIdSalt, encryptionIv);
    }

    public static File getBackupKeyFile() {
        return new File(Decrypt.FILE_BACKUP_KEY);
    }

    public static BackupKey getBackupKeyWithRandomizedIV(String keyFilePath) {
        final File backupKeyFile = new File(keyFilePath);

        final byte[] byteArray = getByteArray(backupKeyFile);
        if (byteArray == null) {
            return null;
        }
        if (byteArray.length < 32 + (16 + (32 + (16 + (32 + (1 + Decrypt.BACKUP_CIPHER_HEADER.length)))))) {
            System.out.println(backupKeyFile.toString() + " size mismatch\n");
            System.exit(0);
        }
        final byte[] header = new byte[Decrypt.BACKUP_CIPHER_HEADER.length];
        System.arraycopy(byteArray, 0, header, 0, Decrypt.BACKUP_CIPHER_HEADER.length);
        final int n = 0 + Decrypt.BACKUP_CIPHER_HEADER.length;
        if (!Arrays.equals(header, Decrypt.BACKUP_CIPHER_HEADER)) {
            System.out.println("Error: Header mismatch\n");
            System.exit(0);
        }
        final int n2 = n + 1;
        final String keyVersion = String.valueOf((int)byteArray[n]);
        final byte[] serverSalt = new byte[32];
        System.arraycopy(byteArray, n2, serverSalt, 0, 32);
        final int n3 = n2 + 32;
        final byte[] googleIdSalt = new byte[16];
        System.arraycopy(byteArray, n3, googleIdSalt, 0, 16);
        final int n4 = n3 + 16;
        final byte[] hashedGoogleId = new byte[32];
        System.arraycopy(byteArray, n4, hashedGoogleId, 0, 32);
        final int n5 = n4 + 32;
        final byte[] generateIV = generateIV();
        final int n6 = n5 + 16;
        final byte[] cipherKey = new byte[32];
        System.arraycopy(byteArray, n6, cipherKey, 0, 32);
        return new BackupKey(header, keyVersion, serverSalt, googleIdSalt, hashedGoogleId, generateIV, cipherKey);
    }

    public static byte[] getByteArray(final File file) {
        ObjectInputStream objectInputStream = null;
        ObjectInputStream objectInputStream2 = null;
        try {
            final ObjectInputStream objectInputStream3;
            objectInputStream2 = (objectInputStream3 = new ObjectInputStream(new FileInputStream(file)));
            final Object o = objectInputStream3.readObject();
            final byte[] array = (byte[])o;
            final byte[] array2 = array;
            final ObjectInputStream objectInputStream4 = objectInputStream2;
            try {
                final ObjectInputStream objectInputStream5 = objectInputStream2;
                objectInputStream5.close();
                return array;
            }
            catch (IOException ex) {
            }
        }
        catch (Exception ex3) {
            return null;
        }
        return null;
    }

    private static byte[] generateIV() {
        return generateRandomBytes(16);
    }

    private static byte[] generateRandomBytes(final int n) {
        try {
            final byte[] array = new byte[n];
            SecureRandom.getInstance("SHA1PRNG").nextBytes(array);
            return array;
        }
        catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static void DecryptDB(String file, byte[] iv, byte[] key) {
        BufferedInputStream is;
        FileOutputStream os;
        RandomAccessFile raf;
        CipherInputStream isCipher;
        Cipher cipher;
        int read;
        byte[] buffer = new byte[32768];

        try{
            // create enc file by stripping header and footer
            is = new BufferedInputStream(new FileInputStream(file));  // read msgstore.db.crypt12
            // 1 + 2 + 32 + 16 + 16 = 67
            is.skip(1 + Decrypt.HEADER_LENGTH + Decrypt.SERVER_SALT_LENGTH + Decrypt.GOOGLE_ID_SALT_LENGTH + Decrypt.ENCRYPTION_IV_LENGTH);
            int available = is.available();
            raf = new RandomAccessFile(new File(Decrypt.FILE_ENC), "rw");

            while((read=is.read(buffer))!=-1) {
                raf.write(buffer, 0, read);
            }
            raf.setLength(available - 20);  // strip 20 byte footer
            raf.close();
        } catch (IOException ex) {
            //
        }


        try {
            is = new BufferedInputStream(new FileInputStream(Decrypt.FILE_ENC));
            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            isCipher = new CipherInputStream(is, cipher);
            InflaterInputStream isInflater = new InflaterInputStream(isCipher, new Inflater(false));
            os = new FileOutputStream(Decrypt.FILE_BACKUP_OUT);

            while((read=isInflater.read(buffer))!=-1) {
                os.write(buffer, 0, read);
            }
            os.close();
            is.close();

            File fileEnc = new File(Decrypt.FILE_ENC);
            if (fileEnc.exists()) {
                fileEnc.delete();
            }
        } catch (Exception ex) {
            System.err.println("Error:" + ex.getMessage());
            ex.printStackTrace();
        }
    }

    public static void logToDisplay(byte[] iv, byte[] key, String keyVersion) {
        System.out.println("Key Version: "+keyVersion);
        System.out.println("IV: "+bytesToHex(iv));
        System.out.println("KEY: "+bytesToHex(key));
    }

    public static void displayTitle() {
        System.out.println("==============================");
        System.out.println("=                            =");
        System.out.println("=     CRYPT12 DECRYPTOR      =");
        System.out.println("=                            =");
        System.out.println("==============================\n");
        System.out.println("Author: mgp25 - https://github.com/mgp25\n");
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] trim(byte[] bytes)
    {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
        {
            --i;
        }

        return Arrays.copyOf(bytes, i + 1);
    }

    public static void doesFileExists(String crypt12File, String keyFile)
    {
        File crypt12file = new File(crypt12File);
        File keyfile = new File(keyFile);

        if (!crypt12file.exists()) {
            System.out.println("Error: " + crypt12File + " doesn't exist");
            System.exit(0);
        }
        if (!keyfile.exists()) {
            System.out.println("Error: " + keyFile + " doesn't exist");
            System.exit(0);
        }
    }
}
