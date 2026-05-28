package com.github.ibmioss.dcmtools;

import java.beans.PropertyVetoException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.github.ibmioss.dcmtools.CertFileImporter.ImportOptions;
import com.github.ibmioss.dcmtools.utils.CertUtils;
import com.github.ibmioss.dcmtools.utils.DcmApiCaller;
import com.github.ibmioss.dcmtools.utils.KeyStoreLoader;
import com.github.ibmioss.dcmtools.utils.TempFileManager;
import com.github.theprez.jcmdutils.AppLogger;
import com.github.theprez.jcmdutils.ConsoleQuestionAsker;
import com.github.theprez.jcmdutils.StringUtils;
import com.github.theprez.jcmdutils.StringUtils.TerminalColor;
import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.ObjectDoesNotExistException;

public class CertRenewer {

    private final List<String> m_fileNames;

    public CertRenewer(final AppLogger _logger, final List<String> _fileNames) throws IOException {
        m_fileNames = new LinkedList<String>();
        for (final String fileName : _fileNames) {
            m_fileNames.add(null == fileName ? KeyStoreLoader.extractTrustFromInstalledCerts(_logger) : fileName);
        }
    }

    public void doRenew(final AppLogger _logger, final ImportOptions _opts) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, InterruptedException, ObjectDoesNotExistException {

        final boolean isYesMode = _opts.isYesMode();

        // Load the certificate file, supporting password-protected files and labels
        final KeyStore keyStore = new KeyStoreLoader(_logger, m_fileNames, _opts.getPasswordOrNull(), _opts.getLabel(), _opts.isCasOnly()).getKeyStore();
        _logger.println_success("Sanity check successful");

        if (!keyStore.aliases().hasMoreElements()) {
            throw new IOException("No certificates to renew");
        }

        // Show what will be renewed
        _logger.println("The following certificates will be renewed in DCM:");
        for (final String alias : Collections.list(keyStore.aliases())) {
            final Certificate cert = keyStore.getCertificate(alias);
            _logger.println("    Certificate ID '" + alias + "':");
            _logger.println(StringUtils.colorizeForTerminal(CertUtils.getCertInfoStr(cert, "        "), TerminalColor.CYAN));
        }

        final String reply = isYesMode ? "y" : ConsoleQuestionAsker.get().askUserWithDefault("Do you want to renew ALL of the above certificates in DCM? [y/N] ", "N");
        if (!reply.toLowerCase().trim().startsWith("y")) {
            throw new IOException("Renewal cancelled");
        }

        // Convert to DCM API format and import, overwriting any existing entry
        final String dcmImportFile = new KeyStoreLoader(keyStore).saveToDcmApiFormatFile(TempFileManager.TEMP_KEYSTORE_PWD);
        try (DcmApiCaller caller = new DcmApiCaller(isYesMode)) {
            caller.callQykmImportKeyStore(_logger, _opts.getDcmStore(), _opts.getDcmPassword(), dcmImportFile, TempFileManager.TEMP_KEYSTORE_PWD);
        }
    }
}
