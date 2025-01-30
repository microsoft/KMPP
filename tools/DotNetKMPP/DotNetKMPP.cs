// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Reflection;
using System.IO;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KMPP
{
    /// <summary>
    /// Provides methods for importing data files and other operations.
    /// </summary>
    public static class DotNetKMPP
    {

        private const string LoggerName = "KMPP_Logger";
        private const string LIB_KMPP = "libkmpp";

        /// <summary>
        /// Represents the status codes for operations.
        /// </summary>
        public enum StatusCode
        {
            /// <summary>
            /// Success with complete chain of certificates to a trusted root.
            /// </summary>
            STATUS_OK = 1,

            /// <summary>
            /// Success with chain error. Might be missing intermediate certs.
            /// *verifyChainError is updated with X509_V_ERR_* error defined in x509_vfy.h.
            /// </summary>
            STATUS_CHAIN_ERROR = -1,

            /// <summary>
            /// Error, unable to import PFX.
            /// </summary>
            STATUS_FAILED = 0
        }

        /// <summary>
        /// Enumeration for Keyiso flags.
        /// </summary>
        [Flags]
        public enum KeyisoFlagsEnum
        {
            /// <summary>
            /// No flags.
            /// </summary>
            None = 0,

            /// <summary>
            /// Skip certificate validation.
            /// </summary>
            SkipValidateCert = 0x10,

            /// <summary>
            /// Key usage for signing.
            /// </summary>
            KeyUsageSign = 0x1000,

            /// <summary>
            /// Key usage for encryption.
            /// </summary>
            KeyUsageEncrypt = 0x2000
        }

        /// <summary>
        /// Static logger instance.
        /// </summary>
        private static ILogger logger;

        /// <summary>
        /// Static constructor to initialize the logger.
        /// </summary>
        static DotNetKMPP()
        {
            logger = CreateDefaultLogger();
        }

        /// <summary>
        /// Gets or sets the logger.
        /// </summary>
        /// <value>The logger instance. Type: <see cref="ILogger"/>.</value>
        public static ILogger Logger
        {
            get => logger;
            set => logger = value ?? CreateDefaultLogger();
        }

        /// <summary>
        /// Creates the default logger.
        /// </summary>
        /// <returns>The default logger instance. Type: <see cref="ILogger"/>.</returns>
        private static ILogger CreateDefaultLogger()
        {
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
            return loggerFactory.CreateLogger(LoggerName);
        }

        /// <summary>
        /// Validates the Key ID.
        /// </summary>
        /// <param name="correlationId">The correlation ID for logging and tracing.</param>
        /// <param name="keyId">The Key ID to validate.</param>
        /// <returns>The status code indicating the result of the validation.</returns>
        [DllImport(LIB_KMPP, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int KeyIso_validate_keyid([MarshalAs(UnmanagedType.LPStruct)] Guid correlationId, string keyId);

        /// <summary>
        /// Imports a PFX file to disk.
        /// </summary>
        /// <param name="correlationId">The correlation ID for logging and tracing.</param>
        /// <param name="keyisoFlags">The flags for the Keyiso operation.</param>
        /// <param name="inPfxLength">The length of the PFX file.</param>
        /// <param name="inPfxBytes">The byte array of the PFX file.</param>
        /// <param name="password">The password for the PFX file.</param>
        /// <param name="verifyChainError">The output parameter for the chain verification error.</param>
        /// <param name="outFilename">The path to the output file.</param>
        /// <returns>The status code indicating the result of the import operation.</returns>
        [DllImport(LIB_KMPP, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int KeyIso_import_pfx_to_disk(
            [MarshalAs(UnmanagedType.LPStruct)] Guid correlationId,
            int keyisoFlags,
            int inPfxLength,
            byte[] inPfxBytes,
            string password,
            out int verifyChainError,
            string outFilename);

        /// <summary>
        /// Validates the Key ID at the specified path.
        /// </summary>
        /// <param name="inKeyIdPath">The path to the Key ID file.</param>
        /// <param name="correlationId">The correlation ID for logging and tracing.</param>
        /// <returns>The status code indicating the result of the validation.</returns>
        public static StatusCode KeyIso_Validate_KeyId(
            string inKeyIdPath, 
            Guid? correlationId = null)
        {
            correlationId ??= Guid.NewGuid(); // Generate a new correlation ID if not provided
            Logger.LogInformation($"Starting ValidateKey. Key ID Path: {inKeyIdPath}, Correlation ID: {correlationId}");

            StatusCode result = (StatusCode)KeyIso_validate_keyid(correlationId.Value, inKeyIdPath);
            Logger.LogInformation($"ValidateKey Result: {result}, Correlation ID: {correlationId}");
            return result;
        }
        /// <summary>
        /// Imports a PFX file to disk.
        /// </summary>
        /// <param name="keyisoFlags">The flags for the Keyiso operation. Type: <see cref="KeyisoFlagsEnum"/>.</param>
        /// <param name="pfxBytes">The byte array of the PFX file. Type: <see cref="byte[]"/>.</param>
        /// <param name="password">The password for the PFX file. Type: <see cref="string"/>.</param>
        /// <param name="verifyChainError">The output parameter for the chain verification error. Type: <see cref="int"/>.</param>
        /// <param name="idFilePath">The path to the ID file. Type: <see cref="string"/>.</param>
        /// <param name="correlationId">The correlation ID for logging and tracing. If null, a new correlation ID will be generated.</param>
        /// <returns>The status code indicating the result of the import operation. Type: <see cref="StatusCode"/>.</returns>
        /// <example>
        /// <code>
        /// int verifyChainError;
        /// StatusCode result = KeyIso_Import_Pfx(
        ///     KeyisoFlagsEnum.SomeFlag,
        ///     File.ReadAllBytes("path/to/pfxfile.pfx"),
        ///     "password",
        ///     out verifyChainError,
        ///     "path/to/idfile.id");
        /// </code>
        /// </example>
        public static StatusCode KeyIso_Import_Pfx(
            KeyisoFlagsEnum keyisoFlags,
            byte[] pfxBytes,
            string password,
            out int verifyChainError,
            string idFilePath,
            Guid? correlationId = null)
        {
            if (pfxBytes == null)
            {
                throw new ArgumentNullException(nameof(pfxBytes), "PFX bytes cannot be null");
            }

            Logger.LogInformation($"Starting ImportPfx. KeyisoFlags: {keyisoFlags}, IdFilePath: {idFilePath}");

            int pfxLength = pfxBytes.Length;

            correlationId ??= Guid.NewGuid(); // Ensure correlationId is not null
            Logger.LogInformation($"Calling native function with Correlation ID: {correlationId}, KeyisoFlags: {keyisoFlags}, IdFilePath: {idFilePath}");
            StatusCode result = (StatusCode)KeyIso_import_pfx_to_disk(correlationId.Value, (int)keyisoFlags, pfxLength, pfxBytes, password, out verifyChainError, idFilePath);
            Logger.LogInformation($"ImportPfx Result: {result}, Correlation ID: {correlationId}");
            return result;
        }
    }
}