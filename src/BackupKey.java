import java.util.Arrays;

public class BackupKey
{
    public BackupCipher cipher;
    public byte[] cipherKey;
    public byte[] hashedGoogleId;

    public BackupKey(final byte[] header, final String keyVersion, final byte[] serverSalt, final byte[] googleIdSalt, final byte[] hashedGoogleId, final byte[] encryptionIv, final byte[] cipherKey) {
        super();
        this.cipher = new BackupCipher(header, keyVersion, serverSalt, googleIdSalt, encryptionIv);
        this.hashedGoogleId = hashedGoogleId;
        this.cipherKey = cipherKey;
    }

    public String toString() {
        return "BackupKey [" + this.cipher.toString() + ", hashedGoogleId=" + Arrays.toString(this.hashedGoogleId) + ", cipherKey=" + Arrays.toString(this.cipherKey) + "]";
    }
}
