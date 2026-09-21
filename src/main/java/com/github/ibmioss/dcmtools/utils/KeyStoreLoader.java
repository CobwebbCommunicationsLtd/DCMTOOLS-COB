package com.github.ibmioss.dcmtools.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.github.theprez.jcmdutils.AppLogger;
import com.github.theprez.jcmdutils.ProcessLauncher;
import com.github.theprez.jcmdutils.ProcessLauncher.ProcessResult;
import com.github.theprez.jcmdutils.StringUtils;

public class KeyStoreLoader {
    private static final String PKCS_12 = "PKCS12";

    public static String extractTrustFromInstalledCerts(final AppLogger _logger) throws IOException {
        final File destFile = TempFileManager.createTempFile(null);
        destFile.delete();
        final ProcessResult cmdResults = ProcessLauncher.exec("/QOpenSys/pkgs/bin/trust extract --format=java-cacerts --purpose=server-auth -v " + destFile.getAbsolutePath());
        if (0 != cmdResults.getExitStatus()) {
            for (final String errLine : cmdResults.getStderr()) {
                _logger.println_err(errLine);
            }
            throw new IOException("Error extracting trusted certificates");
        }
        _logger.println_success("Successfully extracted installed certificates");
        return destFile.getAbsolutePath(); // TODO: delete this file!
    }

    private final KeyStore m_keyStore;

    public KeyStoreLoader(final KeyStore _ks) {
        m_keyStore = _ks;
    }

    public KeyStoreLoader(final AppLogger _logger, final List<String> _files, final String _pw, final String _label, final boolean _caOnly) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

        final List<String> filesToLoad = new LinkedList<String>();
        filesToLoad.addAll(_files);

        // TODO: if .zip file, unzip and process files individually
        for (final String file : _files) {
            final File f = new File(file);
            if (f.isDirectory()) {
                for (final File innerFile : f.listFiles()) {
                    filesToLoad.add(innerFile.getAbsolutePath());
                }
            } else if (file.toLowerCase().endsWith(".zip")) {
                for (final File innerFile : TempFileManager.unzip(file)) {
                    filesToLoad.add(innerFile.getAbsolutePath());
                }
            }
        }

        final String[] keystoreTypes = new String[] { KeyStore.getDefaultType(), "JKS", "PKCS12", "JCEKS", "PKCS12V3" };
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        boolean isKeyStoreLoaded = false;

        for (final String file : filesToLoad) {
            boolean isFileLoaded = false;
            final File fileObj = new File(file);

            // skip directories and .zip files (we already added their contents to the main list)
            if (fileObj.isDirectory() || file.toLowerCase().endsWith(".zip")) {
                continue;
            }
            // Report an unusable file for what it is. Everything below swallows its
            // exceptions in order to try the next format, so without this check a
            // mistyped path (or a '~' the shell never expanded) is indistinguishable
            // from a file we genuinely cannot parse.
            if (!fileObj.exists()) {
                _logger.println_err("ERROR: File " + file + " does not exist");
                continue;
            }
            if (!fileObj.isFile()) {
                _logger.println_err("ERROR: " + file + " is not a regular file");
                continue;
            }
            if (!fileObj.canRead()) {
                _logger.println_err("ERROR: File " + file + " is not readable");
                continue;
            }
            // Try to load as keystore file
            for (final String keystoreType : keystoreTypes) {
                KeyStore fileKs = null;
                try (FileInputStream fis = new FileInputStream(file)) {
                    fileKs = KeyStore.getInstance(keystoreType);
                    fileKs.load(fis, null == _pw ? null : _pw.toCharArray());
                } catch (final Throwable e) {
                    continue;
                }
                if (null != fileKs) {
                    keyStore = CertUtils.mergeKeyStore(keyStore, fileKs, null == _pw ? null : _pw.toCharArray());
                    if (!StringUtils.isEmpty(_label)) {
                        keyStore = CertUtils.relabelKeyStore(keyStore, _label.trim(), TempFileManager.TEMP_KEYSTORE_PWD.toCharArray());
                    }
                    isFileLoaded = true;
                    isKeyStoreLoaded = true;
                    break;
                }
            }
            // That didn't work! Try to load as a certificate file
            Throwable certParseFailure = null;
            int nonCaSkipped = 0;
            if (!isFileLoaded) {
                try (FileInputStream fis = new FileInputStream(file)) {
                    final Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509").generateCertificates(fis);
                    if (!certs.isEmpty()) {
                        int counter = 1;
                        for (final Certificate cert : certs) {
                            if (_caOnly && !isCertCa(cert)) {
                                nonCaSkipped++;
                                continue;
                            }
                            final String aliasBase = StringUtils.isEmpty(_label) ? fileObj.getName().replaceFirst("[.][^.]+$", "") : _label.trim();
                            final String aliasSuffix = (1 == counter) ? "" : "." + counter;
                            counter++;
                            final String alias = aliasBase + aliasSuffix;
                            keyStore.setCertificateEntry(alias, cert);
                            isFileLoaded = true;
                        }
                    }
                } catch (final Throwable e) {
                    certParseFailure = e;
                }
            }
            if (!isFileLoaded) {
                if (0 < nonCaSkipped) {
                    // The file parsed fine, it just held nothing we were asked to keep
                    _logger.println_warn("WARNING: File " + fileObj.getName() + " will not be processed. It holds " + nonCaSkipped + " certificate(s), none of which are CA certificates");
                } else {
                    _logger.println_warn("WARNING: File " + fileObj.getName() + " will not be processed. It is in an unsupported format");
                    if (null != certParseFailure) {
                        _logger.printExceptionStack_verbose(certParseFailure);
                    }
                }
            }
        }
        // Out of ideas. A keystore file that loaded and then yielded no entries is
        // a failure too, not an empty input -- the previous condition let that case
        // through, and it reached the caller as "No certificates to import", which
        // reads as "your file had nothing new in it" and sent an investigation off
        // in entirely the wrong direction.
        if (!keyStore.aliases().hasMoreElements()) {
            throw new IOException(isKeyStoreLoaded
                    ? "A keystore file loaded successfully but no certificates survived processing. This is a bug, not an empty input file."
                    : "Failure loading certificates");
        }
        _logger.println_verbose("Successfully loaded certificates");
        m_keyStore = keyStore;
    }

    public KeyStore getKeyStore() {
        return m_keyStore;
    }

    private boolean isCertCa(final Certificate cert) {
        if (cert instanceof X509Certificate) {
            return ((X509Certificate) cert).getBasicConstraints() != -1;
        }
        return false;
    }

    public String saveToDcmApiFormatFile(final String _pw) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        final KeyStore keyStore = getKeyStore();
        final File dcmFile = TempFileManager.createTempFile(null);
        final KeyStore tgt = KeyStore.getInstance(PKCS_12);
        tgt.load(null, _pw.toCharArray());
        for (final String alias : Collections.list(keyStore.aliases())) {
            if (keyStore.isKeyEntry(alias)) {
                try {
                    final Key key = keyStore.getKey(alias, TempFileManager.TEMP_KEYSTORE_PWD.toCharArray());
                    final Certificate[] chain = keyStore.getCertificateChain(alias);
                    if (key != null && chain != null) {
                        tgt.setKeyEntry(alias, key, _pw.toCharArray(), chain);
                        continue;
                    }
                } catch (final Exception e) { /* fall through to certificate-only entry */ }
            }
            tgt.setCertificateEntry(alias, keyStore.getCertificate(alias));
        }
        try (FileOutputStream fos = new FileOutputStream(dcmFile, true)) {
            tgt.store(fos, _pw.toCharArray());
        }
        return dcmFile.getAbsolutePath();
    }
}
