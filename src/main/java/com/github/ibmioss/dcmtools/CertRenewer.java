package com.github.ibmioss.dcmtools;

import java.beans.PropertyVetoException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.github.ibmioss.dcmtools.CertFileImporter.ImportOptions;
import com.github.ibmioss.dcmtools.utils.CertUtils;
import com.github.ibmioss.dcmtools.utils.KeyStoreLoader;
import com.github.theprez.jcmdutils.AppLogger;
import com.github.theprez.jcmdutils.ConsoleQuestionAsker;
import com.github.theprez.jcmdutils.StringUtils;
import com.github.theprez.jcmdutils.StringUtils.TerminalColor;
import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.ObjectDoesNotExistException;

public class CertRenewer {

    private static final String DCM_KEYSTORE_TYPE = "IBMi5OSKeyStore";

    private final List<String> m_fileNames;

    public CertRenewer(final AppLogger _logger, final List<String> _fileNames) throws IOException {
        m_fileNames = new LinkedList<String>();
        for (final String fileName : _fileNames) {
            m_fileNames.add(null == fileName ? KeyStoreLoader.extractTrustFromInstalledCerts(_logger) : fileName);
        }
    }

    public void doRenew(final AppLogger _logger, final ImportOptions _opts) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, InterruptedException, ObjectDoesNotExistException {

        final boolean isYesMode = _opts.isYesMode();

        // Load the new certificate file, supporting password-protected files and labels
        final KeyStore newCerts = new KeyStoreLoader(_logger, m_fileNames, _opts.getPasswordOrNull(), _opts.getLabel(), _opts.isCasOnly()).getKeyStore();
        _logger.println_success("Sanity check successful");

        if (!newCerts.aliases().hasMoreElements()) {
            throw new IOException("No certificates to renew");
        }

        // A fullchain file arrives as 'label', 'label.2', 'label.3'... Group those back
        // together so the leaf is renewed and the rest become its issuer chain.
        final Map<String, List<Certificate>> renewals = groupIntoChains(newCerts);

        // Open the DCM store directly. The QYKMIMPK ("import key") API cannot do this job:
        // it needs a private key in the import file, and it refuses to overwrite a
        // certificate ID that already exists -- which is precisely the renewal case.
        final String dcmStore = _opts.getDcmStore();
        final char[] dcmPw = _opts.getDcmPassword().toCharArray();
        final KeyStore dcm = KeyStore.getInstance(DCM_KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(dcmStore)) {
            dcm.load(fis, dcmPw);
        }

        // Validate every renewal before touching the store, so we never half-apply
        for (final Map.Entry<String, List<Certificate>> renewal : renewals.entrySet()) {
            validateRenewal(dcm, renewal.getKey(), renewal.getValue().get(0));
        }

        // Show what will be renewed
        _logger.println("The following certificates will be renewed in DCM:");
        for (final Map.Entry<String, List<Certificate>> renewal : renewals.entrySet()) {
            final String certId = renewal.getKey();
            _logger.println("    Certificate ID '" + certId + "':");
            _logger.println("      REPLACING:");
            _logger.println(StringUtils.colorizeForTerminal(CertUtils.getCertInfoStr(dcm.getCertificate(certId), "        "), TerminalColor.YELLOW));
            _logger.println("      WITH:");
            _logger.println(StringUtils.colorizeForTerminal(CertUtils.getCertInfoStr(renewal.getValue().get(0), "        "), TerminalColor.CYAN));
        }

        final String reply = isYesMode ? "y" : ConsoleQuestionAsker.get().askUserWithDefault("Do you want to renew ALL of the above certificates in DCM? [y/N] ", "N");
        if (!reply.toLowerCase().trim().startsWith("y")) {
            throw new IOException("Renewal cancelled");
        }

        // Swap in the new certificate, keeping the private key that is already in DCM
        for (final Map.Entry<String, List<Certificate>> renewal : renewals.entrySet()) {
            final String certId = renewal.getKey();
            final Key existingKey;
            try {
                existingKey = dcm.getKey(certId, dcmPw);
            } catch (final UnrecoverableKeyException e) {
                throw new IOException("Unable to recover the private key for '" + certId + "' from DCM: " + e.getLocalizedMessage(), e);
            }
            final List<Certificate> chain = renewal.getValue();
            dcm.setKeyEntry(certId, existingKey, dcmPw, chain.toArray(new Certificate[chain.size()]));
        }
        try (FileOutputStream fos = new FileOutputStream(dcmStore)) {
            dcm.store(fos, dcmPw);
        }

        verifyRenewalApplied(_logger, dcmStore, dcmPw, renewals);
    }

    /**
     * Groups the aliases produced by {@link KeyStoreLoader} back into certificate
     * chains. The loader labels a multi-certificate (fullchain) file as
     * <code>label</code>, <code>label.2</code>, <code>label.3</code>..., so the
     * unsuffixed alias is the leaf and the suffixed ones are its issuers, in order.
     */
    private Map<String, List<Certificate>> groupIntoChains(final KeyStore _newCerts) throws KeyStoreException, IOException {
        final Map<String, List<Certificate>> ret = new LinkedHashMap<String, List<Certificate>>();
        final List<String> aliases = Collections.list(_newCerts.aliases());
        // leaves first, so the chain lists are always seeded by the unsuffixed alias
        for (final String alias : aliases) {
            if (alias.equals(baseAlias(alias))) {
                final List<Certificate> chain = new LinkedList<Certificate>();
                chain.add(_newCerts.getCertificate(alias));
                ret.put(alias, chain);
            }
        }
        for (final String alias : aliases) {
            final String base = baseAlias(alias);
            if (alias.equals(base)) {
                continue;
            }
            final List<Certificate> chain = ret.get(base);
            if (null == chain) {
                throw new IOException("Certificate '" + alias + "' has no corresponding leaf certificate '" + base + "'");
            }
            chain.add(_newCerts.getCertificate(alias));
        }
        return ret;
    }

    private String baseAlias(final String _alias) {
        return _alias.replaceFirst("[.][0-9]+$", "");
    }

    /**
     * Renders a serial number the way DCM and openssl do. {@link BigInteger#toString(int)}
     * drops the leading zero nibble of a serial whose first byte is below 0x10, which
     * makes an otherwise identical serial look different from the one those tools report.
     */
    private static String formatSerial(final BigInteger _serial) {
        final String hex = _serial.toString(16).toUpperCase();
        return (0 == hex.length() % 2) ? hex : "0" + hex;
    }

    private void validateRenewal(final KeyStore _dcm, final String _certId, final Certificate _newCert) throws KeyStoreException, IOException {
        if (!_dcm.containsAlias(_certId)) {
            throw new IOException("Certificate ID '" + _certId + "' does not exist in DCM. Use 'dcmimport' to add a new certificate, or --cert=<id> to name an existing one");
        }
        if (!_dcm.isKeyEntry(_certId)) {
            throw new IOException("Certificate ID '" + _certId + "' has no private key in DCM, so it cannot be renewed. Use 'dcmimport' instead");
        }
        // Renewal keeps the private key that is already in DCM, so the new certificate
        // must certify that same key pair. It will not if the CSR was generated against
        // a freshly-created key rather than the one held in DCM.
        final PublicKey dcmKey = _dcm.getCertificate(_certId).getPublicKey();
        if (!dcmKey.equals(_newCert.getPublicKey())) {
            throw new IOException("The new certificate for '" + _certId + "' certifies a different public key than the one currently in DCM, so the private key stored in DCM cannot be reused."
                    + " Renew using a CSR generated from the existing DCM key, or import the new certificate together with its matching private key (build a PKCS12 with"
                    + " 'openssl pkcs12 -export -inkey <key> -in <fullchain> -name " + _certId + " -out new.p12', remove the old entry with 'dcmremovecert', then 'dcmimport --password=...')");
        }
    }

    /**
     * Re-reads the store from disk and confirms the certificate actually changed, so
     * that a reported success always reflects a real change.
     */
    private void verifyRenewalApplied(final AppLogger _logger, final String _dcmStore, final char[] _dcmPw, final Map<String, List<Certificate>> _renewals) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore reloaded = KeyStore.getInstance(DCM_KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(_dcmStore)) {
            reloaded.load(fis, _dcmPw);
        }
        for (final Map.Entry<String, List<Certificate>> renewal : _renewals.entrySet()) {
            final String certId = renewal.getKey();
            final Certificate expected = renewal.getValue().get(0);
            final Certificate actual = reloaded.getCertificate(certId);
            if (!expected.equals(actual)) {
                throw new IOException("Renewal of '" + certId + "' did not take effect in DCM. The store still holds a different certificate");
            }
            if (expected instanceof X509Certificate) {
                final X509Certificate x = (X509Certificate) expected;
                _logger.println_success("Certificate ID '" + certId + "' now holds serial " + formatSerial(x.getSerialNumber()) + ", valid until " + x.getNotAfter());
            } else {
                _logger.println_success("Certificate ID '" + certId + "' renewed");
            }
        }
        _logger.println_warn("NOTE: restart any servers using these certificates for the change to take effect");
    }
}
