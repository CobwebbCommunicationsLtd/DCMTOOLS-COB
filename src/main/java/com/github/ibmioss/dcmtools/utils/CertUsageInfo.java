package com.github.ibmioss.dcmtools.utils;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.github.ibmioss.dcmtools.DcmUserOpts;
import com.github.theprez.jcmdutils.AppLogger;

/**
 * Looks up which applications currently have a given certificate ID assigned in
 * the *SYSTEM store. This is what lets a renewal snapshot the
 * certificate-to-application assignments beforehand and restore them afterward
 * -- the actual thing that broke silently when a renewal rewrote the store,
 * independent of whether the store's password stash was also involved.
 * <p>
 * Two backends, tried in this order:
 * <ol>
 * <li>IBM's native <code>QycdRetrieveCertUsageInfo</code> API, which is present
 * on every release that has DCM at all;</li>
 * <li>the <code>QSYS2.CERTIFICATE_USAGE_INFO</code> SQL service, which is not --
 * it is absent on, for example, an un-PTF'd 7.4, where relying on it alone left
 * the renewal guard silently inoperative.</li>
 * </ol>
 * The native API is preferred precisely because it is the one that is always
 * there. The SQL service is kept as a fallback rather than removed: it is a
 * completely independent route to the same answer, and this lookup is the thing
 * standing between a failed renewal and a machine with no working SSL.
 */
public final class CertUsageInfo {

    private CertUsageInfo() {
    }

    /**
     * @param _apiCaller used for the native lookup; if null, only the SQL
     *                   service is tried
     * @throws Exception if <em>neither</em> backend could answer. Callers must
     *                   treat that as "I do not know what was assigned", which
     *                   is not the same as "nothing was assigned" -- see
     *                   CertRenewer, which refuses to rewrite the store in that
     *                   state.
     */
    public static List<String> findApplicationsAssignedTo(final AppLogger _logger, final DcmApiCaller _apiCaller, final String _certId) throws Exception {
        if (null != _apiCaller) {
            try {
                return findViaNativeApi(_logger, _apiCaller, _certId);
            } catch (final Exception e) {
                _logger.println_warn("Native certificate-usage lookup failed (" + e.getLocalizedMessage() + "); trying the SQL service instead");
            }
        }
        return findViaSqlService(_certId);
    }

    /**
     * Asks the native API for every application of each type and keeps the ones
     * holding this certificate. The API selects by application, not by
     * certificate, so the filtering happens here.
     */
    private static List<String> findViaNativeApi(final AppLogger _logger, final DcmApiCaller _apiCaller, final String _certId) throws Exception {
        final List<String> ret = new LinkedList<String>();
        for (final String appType : DcmApiCaller.APPLICATION_TYPES) {
            final Map<String, String> assignments = _apiCaller.callQycdRetrieveCertUsageInfo(_logger, appType);
            for (final Map.Entry<String, String> assignment : assignments.entrySet()) {
                // DCM certificate IDs are not case-sensitive -- the keystore
                // underneath them is not either -- so neither is this.
                if (_certId.equalsIgnoreCase(assignment.getValue())) {
                    ret.add(assignment.getKey());
                }
            }
        }
        return ret;
    }

    private static List<String> findViaSqlService(final String _certId) throws SQLException, ClassNotFoundException {
        Class.forName("com.ibm.as400.access.AS400JDBCDriver");
        final List<String> ret = new LinkedList<String>();
        try (Connection conn = DriverManager.getConnection("jdbc:as400://localhost;naming=system")) {
            // An assignment records the store either by its special value or by
            // its path, depending on what the caller that made it passed. Both
            // occur on the same system; matching only '*SYSTEM' quietly misses
            // the others.
            final String sql = "select APPLICATION_ID from QSYS2.CERTIFICATE_USAGE_INFO"
                    + " where CERTIFICATE_STORE in ('*SYSTEM', ?) and CERTIFICATE_LABELS like '%\"' || ? || '\"%'";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, DcmUserOpts.SYSTEM_DCM_STORE);
                stmt.setString(2, _certId);
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        ret.add(rs.getString(1));
                    }
                }
            }
        }
        return ret;
    }
}
