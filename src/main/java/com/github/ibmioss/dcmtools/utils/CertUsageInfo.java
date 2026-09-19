package com.github.ibmioss.dcmtools.utils;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;

/**
 * Looks up which applications currently have a given certificate ID assigned
 * in the *SYSTEM store, via the QSYS2.CERTIFICATE_USAGE_INFO SQL service. This
 * is what lets a renewal snapshot the certificate-to-application assignments
 * beforehand and restore them afterward -- the actual thing that broke
 * silently when a renewal rewrote the store, independent of whether the
 * store's password stash was also involved.
 */
public final class CertUsageInfo {

    private CertUsageInfo() {
    }

    public static List<String> findApplicationsAssignedTo(final String _certId) throws SQLException, ClassNotFoundException {
        Class.forName("com.ibm.as400.access.AS400JDBCDriver");
        final List<String> ret = new LinkedList<String>();
        try (Connection conn = DriverManager.getConnection("jdbc:as400://localhost;naming=system")) {
            final String sql = "select APPLICATION_ID from QSYS2.CERTIFICATE_USAGE_INFO"
                    + " where CERTIFICATE_STORE = '*SYSTEM' and CERTIFICATE_LABELS like '%\"' || ? || '\"%'";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, _certId);
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
