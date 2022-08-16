using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Blindnet.Utils
{
    /// <summary>
    /// Application settings
    /// </summary>
    public static class AppSettings
    {
        /// <summary>
        /// Application ID param name in JWT
        /// </summary>
        public const string TokenAppIDParamName = "app";
        /// <summary>
        /// User ID param name in JWT
        /// </summary>
        public const string TokenUserIDParamName = "uid";
        /// <summary>
        /// User IDs param name in JWT
        /// </summary>
        public const string TokenUserIDsListParamName = "uids";
        /// <summary>
        /// User group ID param name in JWT
        /// </summary>
        public const string TokenUserGroupIDParamName = "gid";
        /// <summary>
        /// Token ID param name in JWT
        /// </summary>
        public const string TokenIDParamName = "tid";
        /// <summary>
        /// Data ID param name in JWT
        /// </summary>
        public const string TokenDataIDParamName = "did";

        /// <summary>
        /// Regular token type name (intended for registered users)
        /// </summary>
        public const string RegularTokenName = "jwt";
        /// <summary>
        /// Client token type name
        /// </summary>
        public const string ClientTokenName = "cjwt";
        /// <summary>
        /// Temporary token type name (intended for non-registered users)
        /// </summary>
        public const string ShortTokenName = "tjwt";
        /// <summary>
        /// Symmetric key token type name
        /// </summary>
        public const string SymmetricKeyTokenName = "sjwt";
        public const string TempTokenName = "tjwt";
    }
}
