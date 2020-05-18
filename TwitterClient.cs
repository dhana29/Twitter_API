using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace TwitterAPI_UsingWebClient
{

    public class TwitterClientMain
    {
        /// <summary>
        /// Main() method
        /// </summary>
        /// <param name="args"></param>
        public static void Main(String[] args)
        {
            var twitter = new TwitterClient("<consumerKey>",
                          "<consumerKeySecret>",
                          "<accessToken>",
                          "<accessTokenSecret>");

            var response = twitter.GetTweets("<User Name>", 5);
        }
    }
    /// <summary>
    /// Twitter Client methods
    /// </summary>
    public class TwitterClient
    {
        public const string OauthVersion = "1.0";
        public const string OauthSignatureMethod = "HMAC-SHA1";

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="consumerKey"></param>
        /// <param name="consumerKeySecret"></param>
        /// <param name="accessToken"></param>
        /// <param name="accessTokenSecret"></param>
        public TwitterClient(string consumerKey, string consumerKeySecret, string accessToken, string accessTokenSecret)
        {
            this.ConsumerKey = consumerKey;
            this.ConsumerKeySecret = consumerKeySecret;
            this.AccessToken = accessToken;
            this.AccessTokenSecret = accessTokenSecret;
        }

        public string ConsumerKey { set; get; }
        public string ConsumerKeySecret { set; get; }
        public string AccessToken { set; get; }
        public string AccessTokenSecret { set; get; }

        /// <summary>
        /// Get Tweets from given User name 
        /// </summary>
        /// <param name="screenName"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public string GetTweets(string screenName, int count)
        {
            string resourceUrl = string.Format("https://api.twitter.com/1.1/statuses/user_timeline.json");

            var requestParameters = new SortedDictionary<string, string>();
            requestParameters.Add("count", count.ToString());
            requestParameters.Add("screen_name", screenName);

            var response = GetResponse(resourceUrl, TwitterMethod.GET, requestParameters);

            return response;
        }
        /// <summary>
        /// Get POST response from HTTPWebMethod
        /// </summary>
        /// <param name="resourceUrl"></param>
        /// <param name="method"></param>
        /// <param name="requestParameters"></param>
        /// <returns></returns>
        private string GetResponse(string resourceUrl, TwitterMethod method, SortedDictionary<string, string> requestParameters)
        {
            ServicePointManager.Expect100Continue = false;
            WebRequest request = null;
            string resultString = string.Empty;

            if (method == TwitterMethod.GET)
            {
                request = (HttpWebRequest)WebRequest.Create(resourceUrl + "?" + requestParameters.ToTwitterWebString());
                request.Method = method.ToString();
            }

            if (request != null)
            {
                var authHeader = CreateHeader(resourceUrl, method, requestParameters);//Twitter API - auth token
                request.Headers.Add("Authorization", authHeader);
                var response = request.GetResponse();

                using (var sd = new StreamReader(response.GetResponseStream()))
                {
                    resultString = sd.ReadToEnd();
                    response.Close();
                }
            }

            return resultString;
        }

        /// <summary>
        /// Authorize the Twitter API - request
        /// </summary>
        /// <param name="resourceUrl"></param>
        /// <param name="method"></param>
        /// <param name="requestParameters"></param>
        /// <returns></returns>
        private string CreateHeader(string resourceUrl, TwitterMethod method,SortedDictionary<string, string> requestParameters)
        {
            var oauthNonce = CreateOauthNonce();
            var oauthTimestamp = CreateOAuthTimestamp();
            var oauthSignature = CreateOauthSignature(resourceUrl, method, oauthNonce, oauthTimestamp, requestParameters);

            //The oAuth signature is then used to generate the Authentication header. 
            const string headerFormat = "OAuth oauth_nonce=\"{0}\", oauth_signature_method =\"{1}\", " + "oauth_timestamp=\"{2}\", oauth_consumer_key =\"{3}\", " + "oauth_token=\"{4}\", oauth_signature =\"{5}\", " + "oauth_version=\"{6}\"";

            var authHeader = string.Format(headerFormat,
                                           Uri.EscapeDataString(oauthNonce),
                                           Uri.EscapeDataString(OauthSignatureMethod),
                                           Uri.EscapeDataString(oauthTimestamp),
                                           Uri.EscapeDataString(ConsumerKey),
                                           Uri.EscapeDataString(AccessToken),
                                           Uri.EscapeDataString(oauthSignature),
                                           Uri.EscapeDataString(OauthVersion)
                );

            return authHeader;
        }

        private string CreateOauthNonce()
        {
            return Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString()));
        }

        private string CreateOauthSignature(string resourceUrl, TwitterMethod method, string oauthNonce, string oauthTimestamp, SortedDictionary<string, string> requestParameters)
        {
            //Add the standard oauth parameters to the sorted list
            requestParameters.Add("oauth_consumer_key", ConsumerKey);
            requestParameters.Add("oauth_nonce", oauthNonce);
            requestParameters.Add("oauth_signature_method", OauthSignatureMethod);
            requestParameters.Add("oauth_timestamp", oauthTimestamp);
            requestParameters.Add("oauth_token", AccessToken);
            requestParameters.Add("oauth_version", OauthVersion);

            var sigBaseString = requestParameters.ToTwitterWebString();

            var signatureBaseString = string.Concat(method.ToString(), "&", Uri.EscapeDataString(resourceUrl), "&",Uri.EscapeDataString(sigBaseString.ToString()));

            //Using this base string, we then encrypt the data using a composite of the 
            //secret keys and the HMAC-SHA1 algorithm.
            var compositeKey = string.Concat(Uri.EscapeDataString(ConsumerKeySecret), "&",
                                             Uri.EscapeDataString(AccessTokenSecret));

            string oauthSignature;
            using (var hasher = new HMACSHA1(Encoding.ASCII.GetBytes(compositeKey)))
            {
                oauthSignature = Convert.ToBase64String(
                    hasher.ComputeHash(Encoding.ASCII.GetBytes(signatureBaseString)));
            }

            return oauthSignature;
        }

        private static string CreateOAuthTimestamp()
        {

            var nowUtc = DateTime.UtcNow;
            var timeSpan = nowUtc - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var timestamp = Convert.ToInt64(timeSpan.TotalSeconds).ToString();

            return timestamp;
        }
    }
    /// <summary>
    /// HTTPWebMethod enums
    /// </summary>
    public enum TwitterMethod
    {
        POST,
        GET
    }

    /// <summary>
    /// Twitter Client Extension Class
    /// </summary>
    public static class TwitterExtensions
    {
        /// <summary>
        /// Convert to Web String
        /// </summary>
        /// <param name="source"></param>
        /// <returns></returns>
        public static string ToTwitterWebString(this SortedDictionary<string, string> source)
        {
            var body = new StringBuilder();

            foreach (var requestParameter in source)
            {
                body.Append(requestParameter.Key);
                body.Append("=");
                body.Append(Uri.EscapeDataString(requestParameter.Value));
                body.Append("&");
            }
            body.Remove(body.Length - 1, 1);

            return body.ToString();
        }
    }
}
