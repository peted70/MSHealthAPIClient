using Newtonsoft.Json;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Data.Json;
using Windows.Security.Authentication.Web;
using Windows.Security.Credentials;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.Web.Http;
using Windows.Web.Http.Headers;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace MSHealthAPIClient
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private const string Scopes = "mshealth.ReadDevices mshealth.ReadActivityHistory mshealth.ReadActivityLocation mshealth.ReadDevices mshealth.ReadProfile offline_access";
        private const string RedirectUri = "https://login.live.com/oauth20_desktop.srf";

        private static string ClientId = string.Empty;
        private static string ClientSecret = string.Empty;

        private const string ClientAppResourceName = "MSHealthClientId";
        private const string ResourceName = "MSHealthOauthToken";
        private const string RefreshResourceName = "MSHealthOauthTokenRefresh";
        private const string UserName = "User";

        private const string ApiVersion = "v1";

        public MainPage()
        {
            InitializeComponent();
            Loaded += OnLoaded;
        }

        private static Uri CreateOAuthCodeRequestUri()
        {
            UriBuilder uri = new UriBuilder("https://login.live.com/oauth20_authorize.srf");
            var query = new StringBuilder();

            query.AppendFormat("redirect_uri={0}", Uri.EscapeUriString(RedirectUri));

            query.AppendFormat("&client_id={0}", Uri.EscapeUriString(ClientId));
            query.AppendFormat("&client_secret={0}", Uri.EscapeUriString(ClientSecret));

            query.AppendFormat("&scope={0}", Uri.EscapeUriString(Scopes));
            query.Append("&response_type=code");

            uri.Query = query.ToString();
            return uri.Uri;
        }

        private static Uri CreateOAuthTokenRequestUri(string code, string refreshToken = "")
        {
            UriBuilder uri = new UriBuilder("https://login.live.com/oauth20_token.srf");
            var query = new StringBuilder();

            query.AppendFormat("redirect_uri={0}", Uri.EscapeUriString(RedirectUri));
            query.AppendFormat("&client_id={0}", Uri.EscapeUriString(ClientId));
            query.AppendFormat("&client_secret={0}", Uri.EscapeUriString(ClientSecret));

            string grant = "authorization_code";
            if (!string.IsNullOrEmpty(refreshToken))
            {
                grant = "refresh_token";
                query.AppendFormat("&refresh_token={0}", Uri.EscapeUriString(refreshToken));
            }
            else
            {
                query.AppendFormat("&code={0}", Uri.EscapeUriString(code));
            }

            query.Append(string.Format("&grant_type={0}", grant));
            uri.Query = query.ToString();
            return uri.Uri;
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            // try to get Client Id And Client Secret from the Password Vault - if no 
            // entry found put up a dialog box to request..
            var appCredentials = GetTokenFromVault(ClientAppResourceName);
            if (string.IsNullOrEmpty(appCredentials.Item1))
            {
                // Put up a UI prompting for the app IDs...
                var cdr = await ClientCredentialsDlg.ShowAsync();
                if (cdr == ContentDialogResult.Primary)
                {
                    ClientId = ClientIdInput.Text;
                    ClientSecret = ClientSecretInput.Text;

                    AddTokenToVault(ClientAppResourceName, ClientId, ClientSecret);
                }
            }
            else
            {
                ClientId = appCredentials.Item1;
                ClientSecret = appCredentials.Item2;
            }
        }

        private async Task<string> MakeRequestAsync(string path, string query = "")
        {
            var token = await GetTokenAsync();
            var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new HttpCredentialsHeaderValue("Bearer", token);

            var ub = new UriBuilder("https://api.microsofthealth.net");

            ub.Path = ApiVersion + "/" + path;
            ub.Query = query;

            string resStr = string.Empty;

            var resp = await http.GetAsync(ub.Uri);

            if (resp.StatusCode == HttpStatusCode.Unauthorized)
            {
                // If we are unauthorized here assume that our token may have expired and use the 
                // refresh token to get a new one and then try the request again..
                var currentToken = GetTokenFromVault(RefreshResourceName);
                string rt = currentToken.Item2.Trim('"');
                var newToken = await GetAndSecurelyStoreAuthTokensFromRefreshToken(rt);

                // Re-issue the same request (will use new auth token now)
                return await MakeRequestAsync(path, query);
            }

            if (resp.IsSuccessStatusCode)
            {
                resStr = await resp.Content.ReadAsStringAsync();
            }
            return resStr;
        }

        private void AddTokenToVault(string resName, string userName, string token)
        {
            var vault = new PasswordVault();
            var credential = new PasswordCredential(resName, userName, token);
            vault.Add(credential);
        }

        private Tuple<string, string> GetTokenFromVault(string resName)
        {
            string userName = string.Empty;
            string password = string.Empty;

            var vault = new PasswordVault();
            try
            {
                var credential = vault.FindAllByResource(resName).FirstOrDefault();
                if (credential != null)
                {
                    userName = credential.UserName;
                    password = vault.Retrieve(resName, userName).Password;
                }
            }
            catch (Exception)
            {
            }
            return new Tuple<string, string>(userName, password);
        }

        private async Task<string> GetTokenAsync()
        {
            var token = GetTokenFromVault(ResourceName);
            if (!string.IsNullOrEmpty(token.Item2))
                return token.Item2;

            // want to get SSO behaviour here but if I use the app callback URI it uses SSO but WAB never
            // returns
            var ar = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None,
                CreateOAuthCodeRequestUri(),
                new Uri("https://login.live.com/oauth20_desktop.srf"));

            var rs = ar.ResponseStatus;
            var ed = ar.ResponseErrorDetail;
            var rd = ar.ResponseData;
            var respUri = new Uri(rd);
            var code = respUri.Query.Split('=')[1];

            var authToken = await GetAndSecurelyStoreAuthTokensFromAuthCode(code);
            return authToken;
        }

        private async Task<string> GetAndSecurelyStoreAuthTokensFromAuthCode(string code)
        {
            var tokenUri = CreateOAuthTokenRequestUri(code);

            var http = new HttpClient();
            var resp = await http.GetAsync(tokenUri);
            var result = await resp.Content.ReadAsStringAsync();

            var value = JsonValue.Parse(result).GetObject();
            var authToken = value.GetNamedValue("access_token").ToString();
            var refreshToken = value.GetNamedValue("refresh_token").ToString();

            AddTokenToVault(ResourceName, UserName, authToken);
            AddTokenToVault(RefreshResourceName, UserName, refreshToken);

            return authToken;
        }

        private async Task<string> GetAndSecurelyStoreAuthTokensFromRefreshToken(string refreshToken)
        {
            var tokenUri = CreateOAuthTokenRequestUri(string.Empty, refreshToken);

            var http = new HttpClient();
            var resp = await http.GetAsync(tokenUri);
            var result = await resp.Content.ReadAsStringAsync();

            var value = JsonValue.Parse(result).GetObject();
            var authToken = value.GetNamedValue("access_token").ToString();
            refreshToken = value.GetNamedValue("refresh_token").ToString();

            AddTokenToVault(ResourceName, UserName, authToken);
            AddTokenToVault(RefreshResourceName, UserName, refreshToken);

            return authToken;
        }

        private async void profile_Click(object sender, RoutedEventArgs e)
        {
            var res = await MakeRequestAsync("me/profile");
            // Format the JSON string
            var obj = JsonConvert.DeserializeObject(res);
            res = JsonConvert.SerializeObject(obj, Formatting.Indented);
            TextDisplay.Text = res;
        }

        private async void devices_Click(object sender, RoutedEventArgs e)
        {
            var res = await MakeRequestAsync("me/devices");
            // Format the JSON string
            var obj = JsonConvert.DeserializeObject(res);
            res = JsonConvert.SerializeObject(obj, Formatting.Indented);
            TextDisplay.Text = res;
        }

        private async void summaries_Click(object sender, RoutedEventArgs e)
        {
            var res = await MakeRequestAsync("me/summaries/Daily", 
                string.Format("startTime={0}", DateTime.Now.AddYears(-1).ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'")));

            // Format the JSON string
            var obj = JsonConvert.DeserializeObject(res);
            res = JsonConvert.SerializeObject(obj, Formatting.Indented);
            TextDisplay.Text = res;
        }

        private async Task<string> GetActivity(string activity)
        {
            var res = await MakeRequestAsync("me/Activities/",
                string.Format("startTime={0}&endTime={1}&activityTypes={2}",
                DateTime.Now.AddYears(-1).ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'"),
                DateTime.Now.ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'"),
                activity));

            await Task.Run(() =>
            {
                // Format the JSON string
                var obj = JsonConvert.DeserializeObject(res);
                res = JsonConvert.SerializeObject(obj, Formatting.Indented);
            });

            return res;
        }

        private async void SleepActivityClick(object sender, RoutedEventArgs e)
        {
            TextDisplay.Text = await GetActivity("Sleep");
        }

        private async void FreePlayActivityClick(object sender, RoutedEventArgs e)
        {
            TextDisplay.Text = await GetActivity("FreePlay");
        }

        private async void GuidedWorkoutActivityClick(object sender, RoutedEventArgs e)
        {
            TextDisplay.Text = await GetActivity("GuidedWorkout");
        }

        private async void BikeActivityClick(object sender, RoutedEventArgs e)
        {
            TextDisplay.Text = await GetActivity("Bike");
        }

        private async void GolfActivityClick(object sender, RoutedEventArgs e)
        {
            TextDisplay.Text = await GetActivity("Golf");
        }

        private async void RunActivityClick(object sender, RoutedEventArgs e)
        {
            TextDisplay.Text = await GetActivity("Run");
        }
    }
}
