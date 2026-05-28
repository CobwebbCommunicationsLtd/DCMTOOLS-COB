package com.github.ibmioss.dcmtools;

import java.util.LinkedList;
import java.util.List;

import com.github.ibmioss.dcmtools.CertFileImporter.ImportOptions;
import com.github.ibmioss.dcmtools.utils.TempFileManager;
import com.github.theprez.jcmdutils.AppLogger;
import com.github.theprez.jcmdutils.StringUtils;
import com.github.theprez.jcmdutils.StringUtils.TerminalColor;

/**
 * Main entry point for the application
 *
 * @author Jesse Gorzinski
 */
public class DcmRenewCmd {

    public static void main(final String... _args) {
        final List<String> files = new LinkedList<String>();
        final ImportOptions opts = new ImportOptions();
        for (final String arg : _args) {
            if ("-y".equals(arg)) {
                opts.setYesMode(true);
            } else if ("-v".equals(arg)) {
                opts.setVerbose(true);
            } else if ("-h".equals(arg) || "--help".equals(arg)) {
                printUsageAndExit();
            } else if ("--ca-only".equals(arg)) {
                opts.setCasOnly(true);
            } else if (arg.startsWith("--password=")) {
                opts.setPasswordProtected(true);
                opts.setPassword(DcmUserOpts.extractValue(arg));
            } else if ("--password".equals(arg)) {
                opts.setPasswordProtected(true);
            } else if (arg.startsWith("--dcm-store=")) {
                final String target = DcmUserOpts.extractValue(arg);
                if ("system".equalsIgnoreCase(target) || "*system".equalsIgnoreCase(target)) {
                    opts.setDcmStore(DcmUserOpts.SYSTEM_DCM_STORE);
                } else {
                    opts.setDcmStore(target);
                }
            } else if (arg.startsWith("--dcm-password=")) {
                opts.setDcmPassword(DcmUserOpts.extractValue(arg));
            } else if (arg.startsWith("--cert=")) {
                opts.setLabel(DcmUserOpts.extractValue(arg));
            } else if (arg.startsWith("-")) {
                System.err.println(StringUtils.colorizeForTerminal("ERROR: Unknown option '" + arg + "'", TerminalColor.BRIGHT_RED));
                printUsageAndExit();
            } else {
                files.add(arg);
            }
        }
        final AppLogger logger = AppLogger.getSingleton(opts.isVerbose());
        try {
            if (files.isEmpty()) {
                System.err.println(StringUtils.colorizeForTerminal("ERROR: no input files specified", TerminalColor.BRIGHT_RED));
                printUsageAndExit();
            }
            final CertRenewer off = new CertRenewer(logger, files);
            off.doRenew(logger, opts);
            logger.println_success("SUCCESS!!!");
        } catch (final Exception e) {
            logger.printExceptionStack_verbose(e);
            logger.println_err(e.getLocalizedMessage());
            TempFileManager.cleanup();
            System.exit(-1);
        } finally {
            TempFileManager.cleanup();
        }

    }

    private static void printUsageAndExit() {
        // @formatter:off
		final String usage = "Usage: dcmrenew [options] <filename> [<filename> ...]\n"
		                        + "\n"
		                        + "    Renews (overwrites) an existing certificate in DCM with a new one\n"
		                        + "    from the given file. The private key already stored in DCM is kept.\n"
		                        + "\n"
		                        + "    Valid options include:\n"
                                + "        -y:                            Do not ask for confirmation\n"
                                + "        --password[=password]:         Input file is password-protected (e.g. PFX)\n"
                                + "        --cert=<id>:                   Certificate ID to use when renewing\n"
                                + "        --dcm-store=<system/filename>: Specify the target DCM store (default: *SYSTEM)\n"
                                + "        --dcm-password=<password>:     DCM keystore password\n"
                                ;
		// @formatter:on
        System.err.println(usage);
        System.exit(-1);
    }
}
