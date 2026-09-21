package com.github.ibmioss.dcmtools.utils;

import java.beans.PropertyVetoException;
import java.io.Closeable;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import com.github.ibmioss.dcmtools.DcmUserOpts;
import com.github.theprez.jcmdutils.AppLogger;
import com.github.theprez.jcmdutils.ConsoleQuestionAsker;
import com.github.theprez.jcmdutils.StringUtils;
import com.github.theprez.jcmdutils.StringUtils.TerminalColor;
import com.ibm.as400.access.AS400;
import com.ibm.as400.access.AS400Bin4;
import com.ibm.as400.access.AS400DataType;
import com.ibm.as400.access.AS400Message;
import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.AS400Structure;
import com.ibm.as400.access.AS400Text;
import com.ibm.as400.access.ErrorCodeParameter;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.IFSFile;
import com.ibm.as400.access.ObjectDoesNotExistException;
import com.ibm.as400.access.ProgramCall;
import com.ibm.as400.access.ProgramParameter;
import com.ibm.as400.access.ServiceProgramCall;

public class DcmApiCaller implements Closeable {

    private final AS400 m_conn;

    public DcmApiCaller(final boolean _isYesMode) throws IOException {
        final String osName = System.getProperty("os.name", "");
        if (osName.equalsIgnoreCase("OS/400")) { // Running on IBM i, using JV1
            m_conn = new AS400("localhost", "*CURRENT", "*CURRENT");
        } else if (osName.equalsIgnoreCase("OS400")) { // Running on i, OpenJDK
            if (_isYesMode) {
                throw new IOException("IBM i password not specified. Run in interactive mode or with JV1 Java for this to work.");
            }
            m_conn = new AS400("localhost", System.getProperty("user.name", "*CURRENT"), ConsoleQuestionAsker.get().askUserOrThrow("Enter IBM i password: "));
        } else {
            if (_isYesMode) {
                throw new IOException("Not allowed with '-y'");
            }
            m_conn = new AS400(ConsoleQuestionAsker.get().askUserOrThrow("Enter IBM i system name: "), ConsoleQuestionAsker.get().askUserOrThrow("Enter IBM i user name: "), ConsoleQuestionAsker.get().askUserForPwd("Enter IBM i password: "));
        }
    }

    public void callQycdAddCACertTrust(final AppLogger _logger, final String _dcmStore, final String _dcmStorePw, final String _appId, final String _alias) throws PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        final ServiceProgramCall program = new ServiceProgramCall(m_conn);
        // Initialize the name of the program to run.
        final String programName = "/QSYS.LIB/QICSS.LIB/QYCDCUSG.SRVPGM";
        final ProgramParameter[] parameterList = new ProgramParameter[6];
        // 1 Application ID Input Char(*)
        parameterList[0] = new ProgramParameter(new AS400Text(_appId.length()).toBytes(_appId));
        parameterList[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 2 Length of application ID Input Binary(4)
        parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(_appId.length()));
        parameterList[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 3 Trusted CA certificate ID type Input Char(1)
        parameterList[2] = new ProgramParameter(new AS400Text(1).toBytes("1"));
        parameterList[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 4 Trusted CA certificate ID Input Char(*)
        parameterList[3] = new ProgramParameter(new AS400Text(_alias.length()).toBytes(_alias));
        parameterList[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 5 Length of trusted CA certificate ID Input Binary(4)
        parameterList[4] = new ProgramParameter(new AS400Bin4().toBytes(_alias.length()));
        parameterList[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 6 Error code I/O Char(*)
        final ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
        ec.setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        parameterList[5] = ec;

        program.setProgram(programName, parameterList);
        program.setProcedureName("QycdAddCACertTrust");
        // Run the program.
        runProgram(_logger, program, ec);
    }

    public void callQycdRemoveCertUsage(final AppLogger _logger, final String _dcmStore, final String _dcmStorePw, final String _appId, final String _alias) throws PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        final ServiceProgramCall program = new ServiceProgramCall(m_conn);
        // Initialize the name of the program to run.
        final String programName = "/QSYS.LIB/QICSS.LIB/QYCDCUSG.SRVPGM";
        final ProgramParameter[] parameterList = new ProgramParameter[7];
        // 1 Application ID Input Char(*)
        parameterList[0] = new ProgramParameter(new AS400Text(_appId.length()).toBytes(_appId));
        parameterList[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 2 Length of application ID Input Binary(4)
        parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(_appId.length()));
        parameterList[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 3 Certificate store name Input Char(*)
        parameterList[2] = new ProgramParameter(new AS400Text(_dcmStore.length()).toBytes(_dcmStore));
        parameterList[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 4 Length of certificate store name Input Binary(4)
        parameterList[3] = new ProgramParameter(new AS400Bin4().toBytes(_dcmStore.length()));
        parameterList[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 5 Certificate ID Input Char(*)
        parameterList[4] = new ProgramParameter(new AS400Text(_alias.length()).toBytes(_alias));
        parameterList[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 6 Length of certificate ID Input Binary(4)
        parameterList[5] = new ProgramParameter(new AS400Bin4().toBytes(_alias.length()));
        parameterList[5].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 7 Error code I/O Char(*)
        final ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
        ec.setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        parameterList[6] = ec;

        program.setProgram(programName, parameterList);
        program.setProcedureName("QycdRemoveCertUsage");
        // Run the program.
        runProgram(_logger, program, ec);
    }

    /**
     * Renews a certificate already in the *SYSTEM store, keeping its existing key
     * pair, by importing a signed certificate for that same key pair from
     * {@code _file} (a PEM file; the leaf certificate followed by its issuer
     * chain). Unlike the KeyStore-based renewal path, this goes through IBM's own
     * QycdRenewCertificate API rather than rewriting the store file directly, so
     * it keeps the store's password stash in sync -- the caller needs *ALLOBJ and
     * *SECADM special authority, not the store password, and this only targets
     * *SYSTEM.
     */
    public void callQycdRenewCertificate_RNWC0300(final AppLogger _logger, final String _file) throws PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        // The API's internal base64/certificate check (qycu_checkForBase64Certificate)
        // rejects the file outright (CPF3CF2, "RC=79") if it isn't tagged CCSID 819 --
        // confirmed by testing. A file written by PASE Java/openssl is CCSID 1208
        // (UTF-8) by default, which fails that check even though the bytes are
        // perfectly valid ASCII PEM.
        final IFSFile ifsFile = new IFSFile(m_conn, _file);
        if (!ifsFile.setCCSID(819)) {
            _logger.println_warn("Could not set CCSID 819 on '" + _file + "'; QycdRenewCertificate is likely to reject it.");
        }
        // Like the other QYCD* APIs (QycdUpdateCertUsage etc.), this is a service
        // program under QICSS, not a plain *PGM under QSYS -- confirmed against
        // /QSYS.LIB/QICSS.LIB/QYCDRNWC.SRVPGM on the actual box.
        final ServiceProgramCall program = new ServiceProgramCall(m_conn);
        // Initialize the name of the program to run.
        final String programName = "/QSYS.LIB/QICSS.LIB/QYCDRNWC.SRVPGM";
        final String apiFormat = "RNWC0300";

        final AS400Structure arg0 = new AS400Structure(new AS400DataType[] {
                // 0 0 Binary (4) Offset to certificate path and file name
                new AS400Bin4(),
                // 4 4 Binary (4) Length of certificate path and file name
                new AS400Bin4(),
                // Char (*) Certificate path and file name
                new AS400Text(_file.length()) }); // TODO

        // Set up the parms
        final ProgramParameter[] parameterList = new ProgramParameter[4];

        // 1 Certificate request data Input Char(*)
        parameterList[0] = new ProgramParameter(arg0.toBytes(new Object[] { 8, _file.length(), _file }));
        parameterList[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 2 Length of certificate request data Input Binary(4)
        parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(arg0.getByteLength()));
        parameterList[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 3 Format name Input Char(8)
        parameterList[2] = new ProgramParameter(new AS400Text(8).toBytes(apiFormat));
        parameterList[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 4 Error Code I/O Char(*)
        final ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
        ec.setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        parameterList[3] = ec;

        program.setProgram(programName, parameterList);
        program.setProcedureName("QycdRenewCertificate");
        // Run the program.
        runProgram(_logger, program, ec);
    }

    // RCUI0200 receiver variable header, and the fields this code reads out of a
    // single application entry. Offsets are from IBM's API reference, and were
    // checked against a live system before being relied on: every application
    // the API reported matched what DCM and the actually-served certificates
    // showed. Displacements inside an entry are relative to the start of that
    // entry, not to the receiver variable.
    private static final int RCUI_HDR_BYTES_AVAILABLE = 4;
    private static final int RCUI_HDR_OFFSET_FIRST_ENTRY = 8;
    private static final int RCUI_HDR_NUM_ENTRIES = 12;
    private static final int ENT_DISPLACEMENT_TO_NEXT = 0;
    private static final int ENT_APPLICATION_ID = 4;
    private static final int ENT_APPLICATION_ID_LEN = 100;
    private static final int ENT_CERT_ASSIGNED_INDICATOR = 206;
    private static final int ENT_CERT_ID_TYPE = 207;
    private static final int ENT_DISPLACEMENT_TO_CERT_ID = 212;
    private static final int ENT_LENGTH_OF_CERT_ID = 216;
    private static final int ENT_DISPLACEMENT_TO_CERT_STORE = 224;
    private static final int ENT_LENGTH_OF_CERT_STORE = 228;

    /** Application types accepted by the selection criteria, in the order we ask. */
    public static final String[] APPLICATION_TYPES = { "1" /* server */, "2" /* client */, "4" /* object signing */ };

    private static int bin4(final byte[] _b, final int _off) {
        return ((_b[_off] & 0xff) << 24) | ((_b[_off + 1] & 0xff) << 16) | ((_b[_off + 2] & 0xff) << 8) | (_b[_off + 3] & 0xff);
    }

    /**
     * Builds the "application selection criteria" parameter: a count of entries,
     * followed by that many entries. The leading count is not optional --
     * omitting it is what gets you CPF3CE7, "Number of selection criteria
     * entries not valid", which reads like a complaint about the entry itself.
     */
    private static byte[] buildApplicationTypeCriteria(final String _appType) {
        final byte[] data = new AS400Text(_appType.length()).toBytes(_appType);
        final int entrySize = 16 + data.length;
        final byte[] ret = new byte[4 + entrySize];
        final AS400Bin4 bin4 = new AS400Bin4();
        System.arraycopy(bin4.toBytes(1), 0, ret, 0, 4); // number of criteria entries
        System.arraycopy(bin4.toBytes(entrySize), 0, ret, 4, 4); // size of this entry
        System.arraycopy(bin4.toBytes(1), 0, ret, 8, 4); // comparison operator: equals
        System.arraycopy(bin4.toBytes(2), 0, ret, 12, 4); // control key: application type
        System.arraycopy(bin4.toBytes(data.length), 0, ret, 16, 4);
        System.arraycopy(data, 0, ret, 20, data.length);
        return ret;
    }

    /**
     * The API reports the certificate store either by its special value or by
     * its path, depending on which of the two a caller used when the assignment
     * was made -- both were observed on the same system, in the same call.
     * Matching only "*SYSTEM" therefore silently drops real assignments, which
     * for a snapshot taken to protect them is the worst possible failure.
     */
    private static boolean isSystemStore(final String _store) {
        return "*SYSTEM".equalsIgnoreCase(_store) || DcmUserOpts.SYSTEM_DCM_STORE.equalsIgnoreCase(_store);
    }

    private static String readDisplacedString(final byte[] _rcv, final int _entryOff, final int _dispField, final int _lenField) {
        final int disp = bin4(_rcv, _entryOff + _dispField);
        final int len = bin4(_rcv, _entryOff + _lenField);
        if (0 >= len || 0 >= disp || _entryOff + disp + len > _rcv.length) {
            return "";
        }
        // The certificate ID is documented as a null-terminated string; strip the
        // terminator rather than depending on whether the length counts it.
        final String raw = (String) new AS400Text(len).toObject(_rcv, _entryOff + disp);
        final int nul = raw.indexOf('\0');
        return (0 <= nul ? raw.substring(0, nul) : raw).trim();
    }

    /**
     * Retrieves, for every registered application of the given type, the
     * certificate currently assigned to it out of the <code>*SYSTEM</code>
     * store. This is the native equivalent of the
     * <code>QSYS2.CERTIFICATE_USAGE_INFO</code> SQL service, which is not
     * present on every supported release -- and where it is missing, a renewal
     * that falls back to rewriting the store has nothing to restore assignments
     * from, which is how a machine loses SSL on every host server at once while
     * the ports stay open.
     *
     * @param _appType one of {@link #APPLICATION_TYPES}
     * @return application ID -> assigned certificate ID, for applications with a
     *         certificate assigned out of the *SYSTEM store
     */
    public Map<String, String> callQycdRetrieveCertUsageInfo(final AppLogger _logger, final String _appType)
            throws PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        int rcvLen = 65536;
        for (int attempt = 0; attempt < 4; attempt++) {
            final ServiceProgramCall program = new ServiceProgramCall(m_conn);
            final String programName = "/QSYS.LIB/QICSS.LIB/QYCDCUSG.SRVPGM";
            final ProgramParameter[] parameterList = new ProgramParameter[5];
            // 1 Receiver variable Output Char(*)
            parameterList[0] = new ProgramParameter(rcvLen);
            // 2 Length of receiver variable Input Binary(4)
            parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(rcvLen));
            // 3 Format name Input Char(8)
            parameterList[2] = new ProgramParameter(new AS400Text(8).toBytes("RCUI0200"));
            // 4 Application selection criteria Input Char(*)
            parameterList[3] = new ProgramParameter(buildApplicationTypeCriteria(_appType));
            // 5 Error code I/O Char(*)
            final ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
            parameterList[4] = ec;
            for (final ProgramParameter parm : parameterList) {
                parm.setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            }

            program.setProgram(programName, parameterList);
            program.setProcedureName("QycdRetrieveCertUsageInfo");
            runProgram(_logger, program, ec);

            final byte[] rcv = parameterList[0].getOutputData();
            if (null == rcv || 16 > rcv.length) {
                throw new IOException("QycdRetrieveCertUsageInfo returned no usable data");
            }
            final int bytesAvailable = bin4(rcv, RCUI_HDR_BYTES_AVAILABLE);
            if (bytesAvailable > rcvLen) {
                rcvLen = bytesAvailable + 4096;
                continue;
            }

            final Map<String, String> ret = new LinkedHashMap<String, String>();
            final int numEntries = bin4(rcv, RCUI_HDR_NUM_ENTRIES);
            int off = bin4(rcv, RCUI_HDR_OFFSET_FIRST_ENTRY);
            for (int i = 0; i < numEntries; i++) {
                if (0 > off || off + ENT_LENGTH_OF_CERT_STORE + 4 > rcv.length) {
                    // Better to have no snapshot at all -- which the caller treats as
                    // a reason to stop -- than a half-parsed one it would act on.
                    throw new IOException("QycdRetrieveCertUsageInfo returned an entry outside the receiver variable");
                }
                final String appId = ((String) new AS400Text(ENT_APPLICATION_ID_LEN).toObject(rcv, off + ENT_APPLICATION_ID)).trim();
                final String isAssigned = (String) new AS400Text(1).toObject(rcv, off + ENT_CERT_ASSIGNED_INDICATOR);
                final String certIdType = (String) new AS400Text(1).toObject(rcv, off + ENT_CERT_ID_TYPE);
                // Certificate ID type 1 is a label. Anything else is not something
                // QycdUpdateCertUsage could restore, so do not record it as though
                // it were.
                if ("1".equals(isAssigned) && "1".equals(certIdType)) {
                    final String store = readDisplacedString(rcv, off, ENT_DISPLACEMENT_TO_CERT_STORE, ENT_LENGTH_OF_CERT_STORE);
                    if (isSystemStore(store)) {
                        final String certId = readDisplacedString(rcv, off, ENT_DISPLACEMENT_TO_CERT_ID, ENT_LENGTH_OF_CERT_ID);
                        if (!StringUtils.isEmpty(certId) && !StringUtils.isEmpty(appId)) {
                            ret.put(appId, certId);
                        }
                    }
                }
                final int dispToNext = bin4(rcv, off + ENT_DISPLACEMENT_TO_NEXT);
                if (0 >= dispToNext) {
                    break;
                }
                off += dispToNext;
            }
            return ret;
        }
        throw new IOException("QycdRetrieveCertUsageInfo kept asking for a larger receiver variable than we were willing to allocate");
    }

    public void callQycdUpdateCertUsage(final AppLogger _logger, final String _appId, final String _certStoreName, final String _certId) throws PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        final ServiceProgramCall program = new ServiceProgramCall(m_conn);
        final String programName = "/QSYS.LIB/QICSS.LIB/QYCDCUSG.SRVPGM";
        final ProgramParameter[] parameterList = new ProgramParameter[8];
        // 1 Application ID Input Char(*)
        parameterList[0] = new ProgramParameter(new AS400Text(_appId.length()).toBytes(_appId));
        parameterList[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 2 Length of application ID Input Binary(4)
        parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(_appId.length()));
        parameterList[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 3 Certificate store name Input Char(*)
        parameterList[2] = new ProgramParameter(new AS400Text(_certStoreName.length()).toBytes(_certStoreName));
        parameterList[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 4 Length of certificate store name Input Binary(4)
        parameterList[3] = new ProgramParameter(new AS400Bin4().toBytes(_certStoreName.length()));
        parameterList[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 5 Certificate ID type Input Char(1)
        parameterList[4] = new ProgramParameter(new AS400Text(1).toBytes("1"));
        parameterList[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 6 Certificate ID Input Char(*)
        parameterList[5] = new ProgramParameter(new AS400Text(_certId.length()).toBytes(_certId));
        parameterList[5].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 7 Length of certificate ID Input Binary(4)
        parameterList[6] = new ProgramParameter(new AS400Bin4().toBytes(_certId.length()));
        parameterList[6].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        // 8 Error code I/O Char(*)
        final ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
        ec.setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        parameterList[7] = ec;

        program.setProgram(programName, parameterList);
        program.setProcedureName("QycdUpdateCertUsage");
        // Run the program.
        runProgram(_logger, program, ec);
    }

    public void callQykmExportKeyStore(final AppLogger _logger, final String _dcmStore, final String _dcmStorePw, final String _exportFile, final String _exportFilePw) throws PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        final ProgramCall program = new ProgramCall(m_conn);
        // Initialize the name of the program to run.
        final String programName = "/QSYS.LIB/QYKMEXPK.PGM";
        final ProgramParameter[] parameterList = new ProgramParameter[14];
        // 1 Certificate store path and file Name Input Char(*)
        parameterList[0] = new ProgramParameter(new AS400Text(_dcmStore.length()).toBytes(_dcmStore));
        // 2 Length of certificate store path and file Name Input Binary(4)
        parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(_dcmStore.length()));
        // 3 Format of certificate store path and file Name Input Char(8)
        parameterList[2] = new ProgramParameter(new AS400Text(8).toBytes("OBJN0100"));
        // 4 Certificate store password Input Char(*)
        parameterList[3] = new ProgramParameter(new AS400Text(_dcmStorePw.length(), 1208).toBytes(_dcmStorePw));
        // 5 Length of certificate store password Input Binary(4)
        parameterList[4] = new ProgramParameter(new AS400Bin4().toBytes(_dcmStorePw.length()));
        // 6 CCSID of certificate store password Input Binary(4)
        parameterList[5] = new ProgramParameter(new AS400Bin4().toBytes(1208));
        // 7 Export path and file name Input Char(*)
        parameterList[6] = new ProgramParameter(new AS400Text(_exportFile.length()).toBytes(_exportFile));
        // 8 Length of export path and file name Input Binary(4)
        parameterList[7] = new ProgramParameter(new AS400Bin4().toBytes(_exportFile.length()));
        // 9 Format of import path and file name Input Char(8)
        parameterList[8] = new ProgramParameter(new AS400Text(8).toBytes("OBJN0100"));
        // 10 Version of export file Input Char(10)
        parameterList[9] = new ProgramParameter(new AS400Text(10).toBytes("*PKCS12V3 "));
        // 11 Export file password Input Char(*)
        parameterList[10] = new ProgramParameter(new AS400Text(_exportFilePw.length(), 1208).toBytes(_exportFilePw));
        // 12 Length of export file password Input Binary(4)
        parameterList[11] = new ProgramParameter(new AS400Bin4().toBytes(_exportFilePw.length()));
        // 13 CCSID of export file password Input Binary(4)
        parameterList[12] = new ProgramParameter(new AS400Bin4().toBytes(1208));
        // 14 Error code I/O Char(*)
        final ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
        parameterList[13] = ec;

        program.setProgram(programName, parameterList);
        // Run the program.
        runProgram(_logger, program, ec);
    }

    // QykmImportKeyStore
    public void callQykmImportKeyStore(final AppLogger _logger, final String _dcmStore, final String _dcmStorePw, final String _dcmImportFile, final String _importFilePw)
            throws PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        final ProgramCall program = new ProgramCall(m_conn);
        // Initialize the name of the program to run.
        final String programName = "/QSYS.LIB/QYKMIMPK.PGM";
        // Set up the parms
        final ProgramParameter[] parameterList = new ProgramParameter[14];
        // 1 Certificate store path and file Name Input Char(*)
        parameterList[0] = new ProgramParameter(new AS400Text(_dcmStore.length()).toBytes(_dcmStore));
        // 2 Length of certificate store path and file Name Input Binary(4)
        parameterList[1] = new ProgramParameter(new AS400Bin4().toBytes(_dcmStore.length()));
        // 3 Format of certificate store path and file Name Input Char(8)
        parameterList[2] = new ProgramParameter(new AS400Text(8).toBytes("OBJN0100"));
        // 4 Certificate store password Input Char(*)
        parameterList[3] = new ProgramParameter(new AS400Text(_dcmStorePw.length(), 1208).toBytes(_dcmStorePw));
        // 5 Length of certificate store password Input Binary(4)
        parameterList[4] = new ProgramParameter(new AS400Bin4().toBytes(_dcmStorePw.length()));
        // 6 CCSID of certificate store password Input Binary(4)
        parameterList[5] = new ProgramParameter(new AS400Bin4().toBytes(1208));
        // 7 Import path and file name Input Char(*)
        parameterList[6] = new ProgramParameter(new AS400Text(_dcmImportFile.length()).toBytes(_dcmImportFile));
        // 8 Length of import path and file name Input Binary(4)
        parameterList[7] = new ProgramParameter(new AS400Bin4().toBytes(_dcmImportFile.length()));
        // 9 Format of import path and file name Input Char(8)
        parameterList[8] = new ProgramParameter(new AS400Text(8).toBytes("OBJN0100"));
        // 10 Version of import file Input Char(10)
        parameterList[9] = new ProgramParameter(new AS400Text(10).toBytes("*PKCS12V3 "));
        // 11 Import file password Input Char(*)
        parameterList[10] = new ProgramParameter(new AS400Text(_importFilePw.length(), 1208).toBytes(_importFilePw));
        // 12 Length of import file password Input Binary(4)
        parameterList[11] = new ProgramParameter(new AS400Bin4().toBytes(_importFilePw.length()));
        // 13 CCSID of import file password Input Binary(4)
        parameterList[12] = new ProgramParameter(new AS400Bin4().toBytes(1208));
        // 14 Error code I/O Char(*)
        final ErrorCodeParameter ec = new ErrorCodeParameter(true, true);
        parameterList[13] = ec;

        program.setProgram(programName, parameterList);
        // Run the program.
        runProgram(_logger, program, ec);
    }

    @Override
    public void close() throws IOException {
        m_conn.disconnectAllServices();
    }

    private void runProgram(final AppLogger _logger, final ProgramCall _program, final ErrorCodeParameter _ec) throws AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException {
        if (!_program.run()) {
            for (final AS400Message msg : _program.getMessageList()) {
                // Show each message.
                _logger.println_err("" + msg);
            }
            throw new IOException("DCM API call failure");
        }
        final String errorMessageId = _ec.getMessageID();
        for (final AS400Message msg : _program.getMessageList()) {
            // Show each message.
            _logger.println(StringUtils.colorizeForTerminal("" + msg, TerminalColor.CYAN));
        }
        if (!StringUtils.isEmpty(errorMessageId)) {
            throw new IOException("API gave error message " + new MessageLookerUpper(errorMessageId.trim()));
        }
    }

}
