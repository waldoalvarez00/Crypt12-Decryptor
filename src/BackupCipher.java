import java.util.Arrays;

public class BackupCipher
{
    public byte[] encryptionIv;
    public byte[] googleIdSalt;
    public byte[] header;
    public String keyVersion;
    public byte[] serverSalt;

    public BackupCipher(final byte[] header, final String keyVersion, final byte[] serverSalt, final byte[] googleIdSalt, final byte[] encryptionIv) {
        super();
        this.header = header;
        this.keyVersion = keyVersion;
        this.serverSalt = serverSalt;
        this.googleIdSalt = googleIdSalt;
        this.encryptionIv = encryptionIv;
    }

    public String toString() {
        return "BackupCipher [cipherVersion=" + Arrays.toString(this.header) + " keyVersion=" + this.keyVersion + ", serverSalt=" + Arrays.toString(this.serverSalt) + ", googleIdSalt=" + Arrays.toString(this.googleIdSalt) + ", encryptionIv=" + Arrays.toString(this.encryptionIv) + "]";
    }
}
