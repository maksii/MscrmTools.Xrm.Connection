using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using Microsoft.Xrm.Tooling.Connector;
using Newtonsoft.Json;

namespace McTools.Xrm.Connection.Utils
{
    /// <summary>
    /// Requests OAuth 2.0 client credentials tokens from the authority named in a connection string, for organizations
    /// whose token authority is not validated by Microsoft Entra ID (local or private environments)
    /// </summary>
    class ClientCredentialsAuthOverride : IOverrideAuthHookWrapper
    {
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _scope;
        private readonly Uri _tokenUrl;
        private Token _token;
        private DateTime _expiresOn;

        class Token
        {
            public string access_token;
            public int expires_in;
        }

        public ClientCredentialsAuthOverride(DbConnectionStringBuilder csb)
        {
            var authority = new Uri(csb["Authority"].ToString().TrimEnd('/') + "/");
            if (authority.Scheme != Uri.UriSchemeHttps && !authority.IsLoopback)
                throw new ArgumentException("The authority must use https, unless it is a loopback address");

            _tokenUrl = new Uri(authority, "oauth2/v2.0/token");
            _scope = new Uri(new Uri(csb["Url"].ToString()), "/") + ".default";
            _clientId = csb["ClientId"].ToString();
            _clientSecret = csb["ClientSecret"].ToString();
        }

        public string GetAuthToken(Uri connectedUri)
        {
            if (_token == null || _expiresOn <= DateTime.UtcNow)
            {
                _token = GetAccessToken();
                _expiresOn = DateTime.UtcNow.AddSeconds(_token.expires_in - 60);
            }

            return _token.access_token;
        }

        private Token GetAccessToken()
        {
            var data = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _clientId,
                ["client_secret"] = _clientSecret,
                ["scope"] = _scope
            };

            var req = WebRequest.Create(_tokenUrl);
            req.Method = "POST";
            req.ContentType = "application/x-www-form-urlencoded";
            using (var reqStream = req.GetRequestStream())
            using (var writer = new StreamWriter(reqStream))
            {
                writer.Write(String.Join("&", data.Select(kvp => $"{HttpUtility.UrlEncode(kvp.Key)}={HttpUtility.UrlEncode(kvp.Value)}")));
            }

            using (var resp = req.GetResponse())
            using (var respStream = resp.GetResponseStream())
            using (var reader = new StreamReader(respStream))
            {
                return JsonConvert.DeserializeObject<Token>(reader.ReadToEnd());
            }
        }
    }
}
